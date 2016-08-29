#!/usr/bin/env python3
import gi
gi.require_version('Gst', '1.0')
from gi.repository import GObject, Gst

import io
import threading
import queue
import requests
import cgi
from sh import aplay

SILENCE_DETECTION_INTERVAL = 1000000000
SILENCE_DETECTION_RANGE = (-45, -35)

# http://freesound.org/people/Snapper4298/sounds/177505/
LISTENING_BEEP = "177505__snapper4298__snap-8.wav"
# http://freesound.org/people/grunz/sounds/109663/
ACK_BEEP = "109663__grunz__success-low.wav"
# http://freesound.org/people/Ultranova105/sounds/136756/
TIMEOUT_BEEP = "136756__ultranova105__negative-warning.wav"
# http://freesound.org/people/bone666138/sounds/198841/
ALARM_BEEP = "198841__bone666138__analog-alarm-clock.wav"

class Audio():
    def __init__(self, log, microphone_alsa_device="hw:1"):
        self._log = log
        
        self.microphone_alsa_device = microphone_alsa_device

        self._listening_timeout_timer = None
        
        self._make_speech_pipeline()
        self._make_audio_pipeline()
        self._make_mic_pipeline()

        self.audioQueue = queue.Queue()
        self._audio_eos = threading.Event()
        self.speechQueue = queue.Queue()
        self._speech_eos = threading.Event()

        self.EOSCallback = lambda x, y: None
        self.PlaybackStartedCallback = lambda x, y: None
        self.RecognizeCallback = lambda x, y, z: None
        
        t = threading.Thread(target=self.playAudioFromQueue, daemon=True)
        t.start()
        t = threading.Thread(target=self.playSpeechFromQueue, daemon=True)
        t.start()

    def clearQueue(self, stop=True):
        if stop:
            self._audio_eos.set()
            self.audio_pipeline.set_state(Gst.State.READY)            
            self.audio_player.set_state(Gst.State.READY)

        while True:
            try:
                self.audioQueue.get_nowait()
            except queue.Empty:
                break

    def _waitForNothingPlaying(self):
        while True:
            success, state_audiopipeline, pending  = self.audio_pipeline.get_state(Gst.CLOCK_TIME_NONE)
            success, state_audioplayer, pending    = self.audio_player.get_state(Gst.CLOCK_TIME_NONE)
            success, state_speechpipeline, pending = self.speech_pipeline.get_state(Gst.CLOCK_TIME_NONE)

            self._log.info("state_audiopipeline=%s state_audioplayer=%s state_speechpipeline=%s",
                           state_audiopipeline, state_audioplayer, state_speechpipeline)
            if state_audiopipeline == Gst.State.PLAYING or \
               state_audioplayer == Gst.State.PLAYING or \
               state_speechpipeline == Gst.State.PLAYING:                
                self._log.info("Now waiting for nothing to be playing")
                self._audio_eos.wait()
                self._log.info("And EOS was hit so ready to check again")

                success, state_audiopipeline, pending  = self.audio_pipeline.get_state(Gst.CLOCK_TIME_NONE)
                success, state_audioplayer, pending    = self.audio_player.get_state(Gst.CLOCK_TIME_NONE)
                success, state_speechpipeline, pending = self.speech_pipeline.get_state(Gst.CLOCK_TIME_NONE)

                self._log.info("state_audiopipeline=%s state_audioplayer=%s state_speechpipeline=%s",
                               state_audiopipeline, state_audioplayer, state_speechpipeline)
                if state_audiopipeline != Gst.State.PLAYING and \
                   state_audioplayer != Gst.State.PLAYING and \
                   state_speechpipeline != Gst.State.PLAYING:                
                    break
                else:
                    self._log.info("Was still playing something, so waiting for next EOS")
                    self._audio_eos.clear()
            else:
                self._log.info("Nothing is playing")            
                self._audio_eos.clear()
                break

    def _waitForNoSpeechPlaying(self):
        while True:
            success, state_speechpipeline, pending = self.speech_pipeline.get_state(Gst.CLOCK_TIME_NONE)

            self._log.info("state_speechpipeline=%s", state_speechpipeline)
            if state_speechpipeline == Gst.State.PLAYING:                
                self._log.info("Now waiting for nothing to be playing")
                self._audio_eos.wait()
                self._log.info("And EOS was hit so ready to check again")

                success, state_speechpipeline, pending = self.speech_pipeline.get_state(Gst.CLOCK_TIME_NONE)

                self._log.info("state_speechpipeline=%s", state_speechpipeline)
                if state_speechpipeline != Gst.State.PLAYING:                
                    break
                else:
                    self._log.info("Was still playing something, so waiting for next EOS")
                    self._audio_eos.clear()
            else:
                self._log.info("Nothing is playing")            
                self._audio_eos.clear()
                break
            
    def playAudioFromQueue(self):
        while True:
            self._log.info("Ready to play from queue")
            source, token, content, offsetInMilliseconds = self.audioQueue.get()
            self._log.info("Got some audio from queue")
            self._waitForNothingPlaying()

            # TODO obey offsetInMilliseconds
            if source == "buffer":
                self.audio_pipeline.token = token
                self.audio_pipeline.set_state(Gst.State.PLAYING)
                self.audio_source.emit('push-buffer', content)
                self.PlaybackStartedCallback(self.audio_pipeline, token)
                self.audio_source.emit('end-of-stream')
            elif source == "url":
                # if we try get just HEAD, then opml.radiotime.com can give different content-type!
                url = content
                response = requests.get(url, stream=True)
                self._log.info(response.headers['content-type'])
                ctype, pdict = cgi.parse_header(response.headers['content-type'])
                if ctype in ("audio/x-mpegurl",):
                    self._log.info("Swapping out url for the one in the body")
                    url = response.text
                    self._log.info("Play audio from replaced URL {}".format(url))
                self.audio_player.set_property('uri', url)
                self.audio_player.token = token            
                self.audio_player.set_state(Gst.State.PLAYING)
                self.PlaybackStartedCallback(self.audio_player, token)

    def playSpeechFromQueue(self):
        while True:
            self._log.info("Ready to play from queue")
            token, content = self.speechQueue.get()
            self._log.info("Got some speech from queue")
            self._waitForNoSpeechPlaying()

            self.speech_pipeline.token = token
            self.speech_pipeline.set_state(Gst.State.PLAYING)
            self.speech_source.emit('push-buffer', content)
            self.PlaybackStartedCallback(self.speech_pipeline, token)
            self.speech_source.emit('end-of-stream')

    def TTS(self, text):
        self._log.debug("Producing TTS for: {}".format(text))
        pipeline = Gst.parse_launch("espeak name=espeak rate=-40 ! audioconvert ! " + \
                                    "audioresample ! " + \
                                    "appsink name=appsink")
        pipeline.get_by_name("espeak").set_property("text", text)

        def tts_sample(sink, iobuff):
            sample = sink.emit("pull-sample")
            buffer = sample.get_buffer()
            data = buffer.extract_dup(0, buffer.get_size())
            iobuff.write(data)
            return Gst.FlowReturn.OK
        
        def tts_eos(bus, msg, eos):
            eos.set()

        appsink = pipeline.get_by_name("appsink")
        appsink.set_property("emit-signals", True)
        iobuff = io.BytesIO()
        appsink.connect('new-sample', tts_sample, iobuff)
        caps = Gst.caps_from_string("audio/x-raw, format=S16LE, rate=16000, channels=1")
        appsink.set_property("caps", caps)
        
        bus = pipeline.get_bus()
        bus.enable_sync_message_emission()
        bus.add_signal_watch()
        eos = threading.Event()
        bus.connect('message::eos', tts_eos, eos)
        pipeline.set_state(Gst.State.PLAYING)

        eos.wait()
        iobuff.seek(0)
        pipeline.set_state(Gst.State.NULL)
        self._log.debug("Produced TTS for: {}".format(text))        
        return iobuff

    def Speak(self, text):
        self._log.debug("Speaking: {}".format(text))

    def Alarm(self):
        aplay(ALARM_BEEP, _bg=True)

    def Listen(self, milliseconds=None, dialogid=None):
        success, state_micpipeline, pending = self._mic_pipeline.get_state(Gst.CLOCK_TIME_NONE)
        if state_micpipeline == Gst.State.PLAYING:
            self._log.info("Was already listening")
            aplay(TIMEOUT_BEEP, _bg=True)
            return False
        self._log.info("Starting listening, timeout milliseconds=%s, dialog=%s", milliseconds, dialogid)
        self.audio_pipeline.set_state(Gst.State.READY)
        self.audio_player.set_state(Gst.State.READY)        
        self._waitForNothingPlaying()
        if milliseconds:
            self._listening_timeout_timer = GObject.timeout_add(milliseconds, self.cancelListen)
        aplay(LISTENING_BEEP, _bg=True)
        self._mic_pipeline.dialogid = dialogid
        self.speaking_started = False
        self.silence_count = 0
        self._mic_pipeline.set_state(Gst.State.PLAYING)

    def cancelListen(self):
        if self.speaking_started is False:
            self._log.info("Timed out listening")
            self._mic_pipeline.set_state(Gst.State.PAUSED)
            self._mic_pipeline.dialogid = None
            aplay(TIMEOUT_BEEP, _bg=True)
        return False
            
    def _make_mic_pipeline(self):
        alsa_mic_pipeline = Gst.Pipeline()
        alsasrc = Gst.ElementFactory.make("alsasrc")
        audioconvert = Gst.ElementFactory.make("audioconvert")
        audioresample = Gst.ElementFactory.make("audioresample")
        level = Gst.ElementFactory.make("level")
        appsink = Gst.ElementFactory.make("appsink")
        
        alsa_mic_pipeline.add(alsasrc)
        alsa_mic_pipeline.add(audioconvert)
        alsa_mic_pipeline.add(audioresample)
        alsa_mic_pipeline.add(level)
        alsa_mic_pipeline.add(appsink)

        alsasrc.link(audioconvert)
        audioconvert.link(audioresample)
        audioresample.link(level)
        level.link(appsink)

        appsink.set_property("emit-signals", True)
        alsasrc.set_property("device", self.microphone_alsa_device)
        appsink.connect('new-sample', self._mic_capture_sample)
        # AVS spec
        caps = Gst.caps_from_string("audio/x-raw, format=S16LE, rate=16000, channels=1")
        appsink.set_property("caps", caps)
        level.set_property("interval", SILENCE_DETECTION_INTERVAL)
        bus = alsa_mic_pipeline.get_bus()
        bus.add_signal_watch()
        
        bus.connect('message::element', self._mic_level_watcher)

        bus.connect('message::tag', self.on_tag)
        bus.connect('message::error', self.on_error)
        bus.connect('message::eos', self.on_eos, self.audio_player)
        bus.connect('message::buffering', self.on_buffering)
        bus.connect('message::state-changed', self.on_state_changed)

        alsa_mic_pipeline.dialogid = None
        self._mic_pipeline = alsa_mic_pipeline

    def _mic_capture_sample(self, appsink):
        sample = appsink.emit("pull-sample")
        buffer = sample.get_buffer()
        data = buffer.extract_dup(0, buffer.get_size())
        self.audio_from_mic.put(data)
        #self._log.info("Putting a sample into queue %s", self.audio_from_mic)
        return Gst.FlowReturn.OK
    
    speaking_started = False
    silence_count = 0
    audio_from_mic = queue.Queue()

    def _mic_level_watcher(self, bus, message, *args):
        structure = message.get_structure()
        peak = structure.get_value('peak')[0]
        self._log.info("Peak level %s", peak)
        if peak > SILENCE_DETECTION_RANGE[0] and not self.speaking_started:
            self.audio_from_mic = queue.Queue()
            self._log.info("Speaking started into queue %s", self.audio_from_mic)
            self.speaking_started = True
            if self._listening_timeout_timer:
                GObject.source_remove(self._listening_timeout_timer)
            self.speaking_finished_event = threading.Event()
            self.RecognizeCallback(self.audio_from_mic,
                                   self._mic_pipeline.dialogid,
                                   self.speaking_finished_event)
        if peak < SILENCE_DETECTION_RANGE[1] and self.speaking_started:
            self.silence_count += 1
            if self.silence_count > 2:
                self._log.info("Speaking finished")
                self.speaking_started = False
                self.silence_count = 0
                self._mic_pipeline.set_state(Gst.State.PAUSED)
                self.speaking_finished_event.set()
                aplay(ACK_BEEP, _bg=True)

        return True

    def _make_audio_pipeline(self):
        # Make two - one for URL playing, and one for content we already have
        
        self.audio_player = Gst.ElementFactory.make("playbin", "player")

        # now fit an equalizer into that playbin
        
        equalizer = Gst.ElementFactory.make("equalizer-3bands", "equalizer")
        convert = Gst.ElementFactory.make("audioconvert", "convert")
        
        asink = Gst.ElementFactory.make("autoaudiosink", "audio_sink")

        audiobin = Gst.Bin("audio_sink_bin")
        audiobin.add(equalizer)
        audiobin.add(convert)
        audiobin.add(asink)

        equalizer.link(convert)
        convert.link(asink)

        ghost_pad = Gst.GhostPad.new("sink",
                                     Gst.Element.get_static_pad(equalizer, "sink"))
        ghost_pad.set_active(True)
        audiobin.add_pad(ghost_pad)
        
        self.audio_player.set_property('audio-sink', audiobin)

        bus = self.audio_player.get_bus()
        bus.enable_sync_message_emission()
        bus.add_signal_watch()
        bus.connect('message::tag', self.on_tag)
        bus.connect('message::error', self.on_error)
        bus.connect('message::eos', self.on_eos, self.audio_player)
        bus.connect('message::buffering', self.on_buffering)
        bus.connect('message::state-changed', self.on_state_changed)

        pipeline = Gst.Pipeline("audio_pipeline")
        src = Gst.ElementFactory.make("appsrc")
        mad = Gst.ElementFactory.make("mad")
        convert = Gst.ElementFactory.make("audioconvert")
        volume = Gst.ElementFactory.make("volume")
        sink = Gst.ElementFactory.make("alsasink")

        pipeline.add(src)
        pipeline.add(mad)
        pipeline.add(convert)
        pipeline.add(volume)
        pipeline.add(sink)

        src.link(mad)
        mad.link(convert)
        convert.link(volume)
        volume.link(sink)

        bus = pipeline.get_bus()
        bus.enable_sync_message_emission()
        bus.add_signal_watch()
        bus.connect('message::tag', self.on_tag)
        bus.connect('message::error', self.on_error)
        bus.connect('message::eos', self.on_eos, pipeline)
        bus.connect('message::buffering', self.on_buffering)
        bus.connect('message::state-changed', self.on_state_changed)

        pipeline.token = ''
        
        self.audio_source = src
        self.audio_pipeline = pipeline
    
    def _make_speech_pipeline(self):
        pipeline = Gst.Pipeline("speech_pipeline")
        
        src = Gst.ElementFactory.make("appsrc")
        mad = Gst.ElementFactory.make("mad")
        convert = Gst.ElementFactory.make("audioconvert")
        volume = Gst.ElementFactory.make("volume")
        sink = Gst.ElementFactory.make("alsasink")

        pipeline.add(src)
        pipeline.add(mad)
        pipeline.add(convert)
        pipeline.add(volume)
        pipeline.add(sink)

        src.link(mad)
        mad.link(convert)
        convert.link(volume)
        volume.link(sink)

        bus = pipeline.get_bus()
        bus.enable_sync_message_emission()
        bus.add_signal_watch()
        bus.connect('message::tag', self.on_tag)
        bus.connect('message::error', self.on_error)
        bus.connect('message::eos', self.on_eos, pipeline)
        bus.connect('message::buffering', self.on_buffering)
        bus.connect('message::state-changed', self.on_state_changed)

        pipeline.token = ''
        
        self.speech_source = src
        self.speech_pipeline = pipeline
        
    def on_buffering(self, bus, msg):
        buffer_level = msg.parse_buffering()
        self._log.debug("BUFFER: %s", buffer_level)

    def on_tag(self, bus, msg):
        taglist = msg.parse_tag()
        exists, title = taglist.get_string('title')
        if exists:
            self._log.info(title)

    def on_error(self, bus, msg):
        self._log.info("ERR: %s %s", bus, msg.parse_error())

    def on_eos(self, bus, msg, pipeline):
        self._log.info("EOS: %s %s %s", bus, msg, pipeline)
        pipeline.set_state(Gst.State.READY)
        self._audio_eos.set()
        self.EOSCallback(pipeline, pipeline.token)

    def on_state_changed(self, bus, msg):
        pass
        #self._log.debug("STATE: %s %s from %s", bus, msg.parse_state_changed(), msg.src.get_name())
        #success, state, pending = msg.parse_state_changed()

