#!/usr/bin/env python3
#from hyper.ssl_compat import SSLContext, SSLSocket
from hyper.contrib import HTTP20Adapter
from hyper.http20.response import HTTP20Response
from requests_toolbelt import MultipartEncoder
from shove import Shove
import cgi
import datetime
import dateutil.parser
import h2.connection
import hyper
import io
import json
import logging
import logging.config
import pprint
import pytz
import queue
import requests
import socket
import threading
import time
import uuid
import sys
import os

import gi
gi.require_version('Gst', '1.0')
from gi.repository import GObject, Gst

import audio

class HTTP20Downchannel(HTTP20Response):
    def close(self):
        print("Not closing stream {}".format(self._stream))

class Alexa():
    _api_version = "v20160207"

    _content_cache = {}
    
    def __init__(self, tokens_filename, audio, log):
        self._log = log
        self._audio = audio
        self._tokens_filename = tokens_filename
        self._eventQueue = queue.Queue()
        persist_path = "/tmp"
        for directory in ("alerts", "alerts/all", "alerts/active"):
            d = os.path.join(persist_path, directory)
            if not os.path.exists(d):
                os.mkdir(d)
        # would prefer to use sqlite, but that complains about
        # our threads accessing the same connection - and dbm seems to not
        # store any changes.
        self.allAlerts = Shove("file:///tmp/alerts/all")
        self.activeAlerts = Shove("file:///tmp/alerts/active")
        #print(list(self.allAlerts.values()))
        self._last_user_activity = datetime.datetime.now()
        t = threading.Thread(target=self.eventQueueThread, daemon=True)
        t.start()
        GObject.timeout_add(500, self.alertCheck)
           
    def alertCheck(self):
        #self._log.info("Checking for alerts")
        try:
            now = datetime.datetime.utcnow().replace(tzinfo=pytz.utc)
            for token, alert in self.allAlerts.items():
                #self._log.info(alert)            
                if 'fired' not in alert and alert['scheduledTime'] <= now:
                    self._log.info("Alerting %s", alert)
                    alert['fired'] = True
                    # looks like Shove doesn't notice we changed the mutable dictionary contents
                    del self.allAlerts[token]
                    self.allAlerts[token] = alert
                    self.allAlerts.sync()
                    messageId = uuid.uuid4().hex
                    self._send_event({
                        "header": {
                            "namespace": "Alerts",
                            "name": "AlertStarted",
                            "messageId": messageId
                        },
                        "payload": {
                            "token": token
                            }})
                    self._audio.Alarm()
                    # TODO wait until some kind of ack?
                    messageId = uuid.uuid4().hex
                    self._send_event({
                        "header": {
                            "namespace": "Alerts",
                            "name": "AlertStopped",
                            "messageId": messageId
                        },
                        "payload": {
                            "token": token
                        }})
                    
        except Exception as e:
            # need to ensure we return True
            self._log.warning(e)
        return True

    def eventQueueThread(self):
        conn = hyper.HTTP20Connection('avs-alexa-na.amazon.com:443',
                                            enable_push=True,
                                            force_proto="h2")
        alexa_tokens = self.get_alexa_tokens()
        def handle_downstream():
            directives_stream_id = conn.request('GET',
                                             '/{}/directives'.format(self._api_version),
                                             headers={
                                                 'Authorization': 'Bearer %s' % alexa_tokens['access_token']})
            self._log.info("Alexa: directives stream is %s", directives_stream_id)
            directives_stream = conn._get_stream(directives_stream_id)
            downchannel = HTTP20Downchannel(directives_stream.getheaders(), directives_stream)
            self._log.info("Alexa: status=%s headers=%s", downchannel.status, downchannel.headers)
            ctype, pdict = cgi.parse_header(downchannel.headers['content-type'][0].decode('utf-8'))
            boundary = bytes("--{}".format(pdict['boundary']), 'utf-8')
            self._log.info("Downstream boundary is %s", boundary)
            if downchannel.status != 200:
                self._log.warning(downchannel)
                raise ValueError("/directive requests returned {}".format(downchannel.status))
            return directives_stream, boundary

        directives_stream, downstream_boundary = handle_downstream()
        messageId = uuid.uuid4().hex
        self._send_event(
            {"header": {
                "namespace": "System",
                "name": "SynchronizeState",
                "messageId": messageId
            },
             "payload": {}
         }, expectedStatusCode=204)

        downstream_buffer = io.BytesIO()
        while True:
            #self._log.info("Waiting for event to send to AVS")
            #self._log.info("Connection socket can_read %s", conn._sock.can_read)
            try:
                event, attachment, expectedStatusCode, speakingFinishedEvent = self._eventQueue.get(timeout=0.25)
            except queue.Empty:
                event = None

            while directives_stream.data or (conn._sock and conn._sock.can_read):
                # we want to avoid blocking if the data wasn't for stream directives_stream
                if conn._sock and conn._sock.can_read:
                    conn._recv_cb()
                while directives_stream.data:
                    framebytes = directives_stream._read_one_frame()
                    self._log.info(framebytes)
                    #self._log.info(framebytes.split(downstream_boundary))
                    self._read_response(framebytes, downstream_boundary, downstream_buffer)

            if event is None:
                continue
            metadata = {
                "context": self._context(),
                "event": event
            }
            self._log.debug("Sending to AVS: \n%s", pprint.pformat(metadata))
            payload_list = [('metadata', (None, json.dumps(metadata), 'application/json; charset=UTF-8'))]
            if attachment:
                # in this case, it would be much better to handcraft the Multipart to be able to
                # stream the response up. Handcrafting needed as we would have to omit length header
                payload_list.append((attachment[0], (None, attachment[1], 'application/octet-stream')))

            #m = MultipartEncoder(payload_list)
            #print(m.to_string())

            boundary = uuid.uuid4().hex
            json_part = bytes(u'--{}\r\nContent-Disposition: form-data; name="metadata"\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n{}'.format(boundary, json.dumps(metadata).encode('utf-8')), 'utf-8')
            json_hdr = bytes(u'--{}\r\nContent-Disposition: form-data; name="metadata"\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n'.format(boundary), 'utf-8')
            end_part = bytes("\r\n--{}--".format(boundary), 'utf-8')
            

            headers = {':method': 'POST',
                       ':scheme': 'https',
                       ':path': '/{}/events'.format(self._api_version),
                       'Authorization': 'Bearer %s' % self.get_alexa_tokens()['access_token'],
                       'Content-Type': 'multipart/form-data; boundary={}'.format(boundary)}
            with conn._write_lock:
                stream_id = conn.putrequest(headers[':method'], headers[':path'])
                default_headers = (':method', ':scheme', ':authority', ':path')
                for name, value in headers.items():
                    is_default = name in default_headers
                    conn.putheader(name, value, stream_id, replace=is_default)
                conn.endheaders(final=False, stream_id=stream_id)

            self._log.info("Alexa: Making request using stream %s", stream_id)
            #print(json_part)
            conn.send(json_hdr, final=False, stream_id=stream_id)
            conn.send(json.dumps(metadata).encode('utf-8'), final=False, stream_id=stream_id)            
            
            if attachment:
                hdr = bytes(u'\r\n--{}\r\nContent-Disposition: form-data; name="{}"\r\nContent-Type: application/octet-stream\r\n\r\n{}'.format(boundary, attachment[0], json.dumps(metadata).encode('utf-8')), 'utf-8')
                conn.send(hdr, final=False, stream_id=stream_id)
                AVS_AUDIO_CHUNK_PREFERENCE=320
                #print(speakingFinishedEvent)
                while True:
                    #sys.stdout.write("X ")
                    #sys.stdout.flush()
                    #self._log.info("Getting bytes from queue %s", attachment[1])
                    if isinstance(attachment[1], queue.Queue):
                        try:
                            chunk = attachment[1].get(block=True, timeout=1)
                        except queue.Empty as e:
                            chunk = ''
                    else:
                        chunk = attachment[1].read(AVS_AUDIO_CHUNK_PREFERENCE)
                    #sys.stdout.write(str(len(chunk)))
                    #sys.stdout.write(" x")
                    #sys.stdout.flush()
                    if speakingFinishedEvent and speakingFinishedEvent.is_set():
                        break
                    if chunk:
                        #sys.stdout.write("+")
                        #sys.stdout.flush()                        
                        conn.send(chunk, final=False, stream_id=stream_id)
                    elif speakingFinishedEvent is None:
                        #sys.stdout.write("#")
                        #sys.stdout.flush()                        
                        break
            #sys.stdout.write("=")
            #sys.stdout.flush()                        
            conn.send(end_part, final=True, stream_id=stream_id)
            self._log.info("Alexa: Made request using stream %s", stream_id)
            resp = conn.get_response(stream_id)
            self._log.info("Alexa HTTP status code: %s", resp.status)
            self._log.debug(resp.headers)
            if expectedStatusCode and resp.status != expectedStatusCode:
                self._log.warning("AVS status code unexpected: %s", resp.status)
                self._log.warning(resp.headers)
                self._log.warning(resp.read())
            if resp.status == 200:
                self._read_response(resp)
            
    def ping(self):
        # TODO need to do this within the events thread
        self._conn.request('GET', '/ping',
                           headers={'Authorization': 'Bearer %s' % alexa_tokens['access_token']})
        if resp.status != 200:
            self._log.warning(resp)
            # TODO On a failed PING the connection should be closed and a new connection should be immediately created.
            # TODO https://developer.amazon.com/public/solutions/alexa/alexa-voice-service/docs/managing-an-http-2-connection
            raise ValueError("/ping requests returned {}".format(resp.status))

    def _context(self):
        playbackState = {
            "header": {
                "namespace": "AudioPlayer",
                "name": "PlaybackState"
            },
            "payload": self._get_playback_state()
        }
        volumeState = {
            "header": {
                "namespace": "Speaker",
                "name": "VolumeState"
            },
            "payload": self._get_volume_state()
        }
        speechState = {
            "header": {
                "namespace": "SpeechSynthesizer",
                "name": "SpeechState"
            },
            "payload": self._get_speech_state()
        }
        allAlerts = []
        for token, alert in self.allAlerts.items():
            allAlerts.append({'token': token,
                              'scheduledTime': alert['scheduledTime'].strftime("%Y-%m-%dT%H:%M:%S+0000"),
                              'type': alert['type']})
        activeAlerts = []
        for token, alert in self.activeAlerts.items():
            allAlerts.append({'token': token,
                              'scheduledTime': alert['scheduledTime'].strftime("%Y-%m-%dT%H:%M:%S+0000"),
                              'type': alert['type']})
        alertsState = {
            "header": {
                "namespace": "Alerts",
                "name": "AlertsState"
            },
            "payload": {"allAlerts": allAlerts,
                        "activeAlerts": activeAlerts}
        }
        # speechstate and playbackstate seem to get     # 
        # INVALID_REQUEST_EXCEPTION if sent on a SpeechFinished etc.
        return [volumeState, alertsState]#, speechState, playbackState]
    
    def Recognize(self, fhandle, dialogid=None, speaking_finished_event=None):
        #print("speaking_finished_event={}".format(speaking_finished_event))
        messageId = uuid.uuid4().hex
        dialogRequestId = dialogid or uuid.uuid4().hex
        response = self._send_event(
            {"header": {
                "namespace": "SpeechRecognizer",
                "name": "Recognize",
                "messageId": messageId,
                "dialogRequestId": dialogRequestId
            },
             "payload": {
                 "profile": "CLOSE_TALK",
                 "format": "AUDIO_L16_RATE_16000_CHANNELS_1"}
         }, ('audio', fhandle), speakingFinishedEvent=speaking_finished_event)

    def _read_response(self, response, boundary=None, buffer=None):
        #self._log.debug("_read_response(%s, %s)", response, boundary)
        if boundary:
            endboundary = boundary + b"--"
        else:
            ctype, pdict = cgi.parse_header(response.headers['content-type'][0].decode('utf-8'))
            boundary = bytes("--{}".format(pdict['boundary']), 'utf-8')
            endboundary = bytes("--{}--".format(pdict['boundary']), 'utf-8')    

        on_boundary = False
        in_header = False
        in_payload = False
        first_payload_block = False    
        content_type = None
        content_id = None
        
        def iter_lines(response, delimiter=None):
            pending = None
            for chunk in response.read_chunked():
                #self._log.debug("Chunk size is {}".format(len(chunk)))
                if pending is not None:
                    chunk = pending + chunk
                if delimiter:
                    lines = chunk.split(delimiter)
                else:
                    lines = chunk.splitlines()

                if lines and lines[-1] and chunk and lines[-1][-1] == chunk[-1]:
                    pending = lines.pop()
                else:
                    pending = None

                for line in lines:
                    yield line

            if pending is not None:
                yield pending

        # cache them up to execute after we've downloaded any binary attachments
        # so that they have the content available
        directives = []
        if isinstance(response, bytes):
            buffer.seek(0)            
            lines = (buffer.read() + response).split(b"\r\n")
            buffer.flush()
        else:
            lines = iter_lines(response, delimiter=b"\r\n")
        for line in lines:
            #self._log.debug("iter_line is {}...".format(repr(line)[0:30]))
            if line == boundary or line == endboundary:
                #self._log.debug("Newly on boundary")
                on_boundary = True
                if in_payload:
                    in_payload = False
                    if content_type == "application/json":
                        self._log.info("Finished downloading JSON")                        
                        json_payload = json.loads(payload.getvalue().decode('utf-8'))
                        #self._log.debug(json_payload)
                        if 'directive' in json_payload:
                            directives.append(json_payload['directive'])
                    else:
                        self._log.info("Finished downloading {} which is {}".format(content_type,
                                                                                    content_id))
                        payload.seek(0)
                        # TODO, start to stream this to speakers as soon as we start getting bytes
                        # strip < and >
                        self._content_cache[content_id[1:-1]] = payload
                        
                continue
            elif on_boundary:
                #self._log.debug("Now in header")                
                on_boundary = False
                in_header = True
            elif in_header and line == b"":
                #self._log.debug("Found end of header")
                in_header = False
                in_payload = True
                first_payload_block = True
                payload = io.BytesIO()
                continue

            if in_header:
                #self._log.debug(repr(line))
                if len(line) > 1:
                    header, value = line.decode('utf-8').split(":", 1)
                    ctype, pdict = cgi.parse_header(value)
                    if header.lower() == "content-type":
                        content_type = ctype
                    if header.lower() == "content-id":
                        content_id = ctype

            if in_payload:
                # add back the bytes that our iter_lines consumed
                self._log.info("Found %s bytes of %s %s, first_payload_block=%s",
                               len(line), content_id, content_type, first_payload_block)
                if first_payload_block:
                    first_payload_block = False
                else:
                    payload.write(b"\r\n")
                payload.write(line)

        if buffer is not None:
            if in_payload:
                self._log.info("Didn't see an entire directive, buffering to put at top of next frame")
                buffer.write(payload.read())
            else:
                buffer.write(boundary)
                buffer.write(b"\r\n")
            
        for directive in directives:
            self._handleDirective(directive)

    def PlaybackStartedCallback(self, pipeline, token):
        if pipeline == self._audio.speech_pipeline:
            messageId = uuid.uuid4().hex
            self._send_event({
                "header": {
                    "namespace": "SpeechSynthesizer",
                    "name": "SpeechStarted",
                    "messageId": messageId,
                },
                "payload": {
                    "token": token
                }
            }, expectedStatusCode=204)
        else:
            query_worked, position_ns = pipeline.query_position(Gst.Format.TIME)
            messageId = uuid.uuid4().hex
            self._send_event({
                "header": {
                    "namespace": "AudioPlayer",
                    "name": "PlaybackStarted",
                    "messageId": messageId,
                },
                "payload": {
                    "token": token,
                    "offsetInMilliseconds": int(position_ns / 1000000) if query_worked else 0,
                }
            }, expectedStatusCode=204)
            
    def EOSCallback(self, pipeline, token):
        self._log.info("Finished playing %s with %s", token, pipeline)
        messageId = uuid.uuid4().hex
        if pipeline == self._audio.speech_pipeline:
            self._send_event({
                "header": {
                    "namespace": "SpeechSynthesizer",
                    "name": "SpeechFinished",
                    "messageId": messageId,
                },
                "payload": {
                    "token": token
                }
            }, expectedStatusCode=204)
        else:
            query_worked, position_ns = pipeline.query_position(Gst.Format.TIME)
            self._log.info("Query position %s %s", query_worked, position_ns)

            self._send_event({
                "header": {
                    "namespace": "AudioPlayer",
                    "name": "PlaybackFinished",
                    "messageId": messageId,
                },
                "payload": {
                    "token": token,
                    "offsetInMilliseconds": int(position_ns / 1000000) if query_worked else 0,
                }
            }, expectedStatusCode=204)
            
    def _play_speech(self, detail):
        self._log.info("Play speech {}".format(detail))
        self._audio.speech_pipeline.set_state(Gst.State.READY)
        token = detail['token']
        if detail['url'].startswith("cid:"):
            contentfp = self._content_cache[detail['url'][4:]]
            buffer = Gst.Buffer.new_wrapped(contentfp.read())
            del self._content_cache[detail['url'][4:]]
            self._audio.speechQueue.put((token, buffer))

    def _play_audio(self, detail):
        self._log.debug("Playing audio {}".format(detail))
        
        url = detail['stream']['url']
        token = detail['stream']['token']
        offsetInMilliseconds = detail['stream']['offsetInMilliseconds']
        
        if url.startswith("cid:"):
            self._log.info("Play audio from attachment {}".format(detail))
            contentfp = self._content_cache[url[4:]]
            buffer = Gst.Buffer.new_wrapped(contentfp.read())
            del self._content_cache[url[4:]]
            self._audio.audioQueue.put(("buffer", token, buffer, offsetInMilliseconds))
            
        else:
            self._log.info("Play audio from URL {}".format(detail))
            self._audio.audioQueue.put(("url", token, url, offsetInMilliseconds))
            
    def _get_speech_state(self):
        query_worked, position_ns = self._audio.speech_pipeline.query_position(Gst.Format.TIME)
        success, current, pending = self._audio.speech_pipeline.get_state(Gst.CLOCK_TIME_NONE)

        return {
            "token": self._audio.speech_pipeline.token if current == Gst.State.PLAYING else "",
            "offsetInMilliseconds": int(position_ns / 1000000) if query_worked else 0,
            "playerActivity": "PLAYING" if current == Gst.State.PLAYING else "FINISHED"
        }

    def _get_playback_state(self):
        success, state_audiopipeline, pending  = self._audio.audio_pipeline.get_state(Gst.CLOCK_TIME_NONE)
        success, state_audioplayer, pending    = self._audio.audio_player.get_state(Gst.CLOCK_TIME_NONE)
        if state_audiopipeline == Gst.State.PLAYING:
            query_worked, position_ns = self._audio.audio_pipeline.query_position(Gst.Format.TIME)
            return {
                "token": self._audio.audio_pipeline.token,
                "offsetInMilliseconds": int(position_ns / 1000000) if query_worked else 0,
                "playerActivity": "PLAYING"
            }
        elif state_audioplayer == Gst.State.PLAYING:
            query_worked, position_ns = self._audio.audio_player.query_position(Gst.Format.TIME)
            return {
                "token": self._audio.audio_player.token,
                "offsetInMilliseconds": int(position_ns / 1000000) if query_worked else 0,
                "playerActivity": "PLAYING"
            }
        else:
            return {
                "token": '',
                "offsetInMilliseconds": 0,
                "playerActivity": "IDLE"
            }
    
    def _get_volume_state(self):
        return {
            "volume": int(self._audio.audio_player.get_property('volume') * 100),
            "mute": self._audio.audio_player.get_property('mute')
        }
    
    def _handleDirective(self, directive):
        self._log.info("Handling {}".format(pprint.pformat(directive)))
        namespace, name = directive['header']['namespace'], directive['header']['name']
        if (namespace, name) == ("System", "ResetUserInactivity"):
            self._last_user_activity = datetime.datetime.now()
        elif (namespace, name) == ("SpeechSynthesizer", "Speak"):
            self._play_speech(directive['payload'])
        elif (namespace, name) == ("SpeechRecognizer", "ExpectSpeech"):
            self._audio.Listen(directive['payload']['timeoutInMilliseconds'],
                               directive['header']['dialogRequestId'])
        elif (namespace, name) == ("AudioPlayer", "Play"):
            if directive['payload']['playBehavior'] == "REPLACE_ALL":
                self._audio.clearQueue()
                self._play_audio(directive['payload']['audioItem'])
            elif directive['payload']['playBehavior'] == "ENQUEUE":
                self._play_audio(directive['payload']['audioItem'])
            elif directive['payload']['playBehavior'] == "REPLACE_ENQUEUED":
                self._audio.clearQueue(stop=False)
                self._play_audio(directive['payload']['audioItem'])
        elif (namespace, name) == ("AudioPlayer", "Stop"):
            self._audio.audio_pipeline.set_state(Gst.State.READY)         
            self._audio.audio_player.set_state(Gst.State.READY)
        elif (namespace, name) == ("AudioPlayer", "ClearQueue"):
            if directive['payload']['clearBehavior'] == "CLEAR_ENQUEUED":
                self._audio.clearQueue()
        elif (namespace, name) == ("Speaker", "SetVolume"):
            self._audio.audio_player.set_property('volume', directive['payload']['volume'] / 100.0)
            self._send_volume_changed()
        elif (namespace, name) == ("Speaker", "SetMute"):
            self._audio.audio_player.set_property('mute', directive['payload']['mute'])
            self._send_mute_changed()
        elif (namespace, name) == ("Speaker", "AdjustVolume"):
            self._log.debug("Volume currently %s", self._audio.audio_player.get_property('volume'))
            current_volume = self._audio.audio_player.get_property('volume') * 100
            new_volume = max(0, min(1, (current_volume + directive['payload']['volume']) / 100.0))
            self._audio.audio_player.set_property('volume', new_volume)
            self._log.debug("Volume now %s", self._audio.audio_player.get_property('volume'))
            self._send_volume_changed()            
        elif (namespace, name) == ("Alerts", "SetAlert"):
            self._set_alert(directive['payload']['type'], directive['payload']['scheduledTime'], directive['payload']['token'])
        elif (namespace, name) == ("Alerts", "DeleteAlert"):
            self._delete_alert(directive['payload']['token'])
            
    def _set_alert(self, type_, scheduledTime, token):
        parsed_datetime = dateutil.parser.parse(scheduledTime)
        if not parsed_datetime:
            messageId = uuid.uuid4().hex
            self._send_event({
                "header": {
                    "namespace": "Alerts",
                    "name": "SetAlertFailed",
                    "messageId": messageId
                },
                "payload": {
                    "token": token
                }}, expectedStatusCode=204)
            return

        self.allAlerts[token] = {"type": type_,
                                 "scheduledTime": parsed_datetime}
        self.allAlerts.sync()
        messageId = uuid.uuid4().hex
        self._send_event({
            "header": {
                "namespace": "Alerts",
                "name": "SetAlertSucceeded",
                "messageId": messageId
            },
            "payload": {
                "token": token
            }})

    def _delete_alert(self, token):
        if token not in self.allAlerts:
            messageId = uuid.uuid4().hex
            self._send_event({
                "header": {
                    "namespace": "Alerts",
                    "name": "DeleteAlertFailed",
                    "messageId": messageId
                },
                "payload": {
                    "token": token
                }})
            return

        del self.allAlerts[token]
        self.allAlerts.sync()        
        messageId = uuid.uuid4().hex
        self._send_event({
            "header": {
                "namespace": "Alerts",
                "name": "DeleteAlertSucceeded",
                "messageId": messageId
            },
            "payload": {
                "token": token
            }}, expectedStatusCode=204)

    def _send_volume_changed(self):
        messageId = uuid.uuid4().hex
        self._send_event({
            "header": {
                "namespace": "Speaker",
                "name": "VolumeChanged",
                "messageId": messageId
            },
            "payload": {
                "volume": int(self._audio.audio_player.get_property('volume') * 100),
                "muted": self._audio.audio_player.get_property('mute')
            }}, expectedStatusCode=204)

    def _send_mute_changed(self):
        messageId = uuid.uuid4().hex
        self._send_event({
            "header": {
                "namespace": "Speaker",
                "name": "VolumeChanged",
                "messageId": messageId
            },
            "payload": {
                "volume": int(self._audio.audio_player.get_property('volume') * 100),
                "muted": self._audio.audio_player.get_property('mute')
            }}, expectedStatusCode=204)
        
    def _send_event(self, event, attachment=None, expectedStatusCode=None, speakingFinishedEvent=None):
        self._eventQueue.put((event, attachment, expectedStatusCode, speakingFinishedEvent))
    
    def get_alexa_tokens(self):
        date_format = "%a %b %d %H:%M:%S %Y"

        alexa_tokens = json.loads(open(self._tokens_filename,'r').read())

        if 'access_token' in alexa_tokens:
            if 'expiry' in alexa_tokens:
                expiry = datetime.datetime.strptime(alexa_tokens['expiry'], date_format)
                # refresh 60 seconds early to avoid chance of using expired access_token
                if (datetime.datetime.utcnow() - expiry) > datetime.timedelta(seconds=60):
                    self._log.info("Refreshing access_token")
                else:
                    self._log.info("access_token should be OK, expires %s", expiry)                
                    return alexa_tokens


        payload = {'client_id': alexa_tokens['client_id'],
                   'client_secret': alexa_tokens['client_secret'],
                   'grant_type': 'refresh_token',
                   'refresh_token': alexa_tokens['refresh_token']}

        conn = hyper.HTTPConnection('api.amazon.com:443', secure=True, force_proto="h2")        
        conn.request("POST", "/auth/o2/token",
                     headers={'Content-Type': "application/json"},
                     body=json.dumps(payload).encode('utf-8'))
        r = conn.get_response()        
        self._log.info(r.status)
        tokens = json.loads(r.read().decode('utf-8'))
        self._log.info(tokens)
        expiry_time = datetime.datetime.utcnow() + datetime.timedelta(seconds=tokens['expires_in'])
        tokens['expiry'] = expiry_time.strftime(date_format)
        payload.update(tokens)
        open(self._tokens_filename,'w').write(json.dumps(payload))
        return payload
        
    def talk_button_pressed(self):
        log.info("Alexa invoked")
        player.set_state(Gst.State.PAUSED)    
        speak("Listening")
        time.sleep(1)
        #aplay("/home/pi/kitchen-music/alexa-beep.wav", _bg=True)
        log.info("Starting alexa microphone pipeline to PLAYING")
        alsa_mic_pipeline.set_state(Gst.State.PLAYING)
        alexapipeline.set_state(Gst.State.READY)

if __name__ == "__main__":
    logging.config.dictConfig({
        'version': 1,
        'formatters': {
            'default': {
                'format': "%(asctime)-15s %(module)-15s %(process)d %(threadName)s %(levelname)-8s %(message)s"
            }
        },
        'handlers': {
            'stdout': {'class': 'logging.StreamHandler',
                       'formatter': 'default',
                       'level': "DEBUG",
                   },
        },
        'loggers': {
            'root': {'handlers': ['stdout'],
                     'level': 'DEBUG'
                 },
        }
    })
    log = logging.getLogger("root")
    
    GObject.threads_init()
    Gst.init(None)
    
    audio = audio.Audio(log, microphone_alsa_device="hw:2")
    
    def alexa_thread():
        alexa = Alexa("tokens.json", audio, log)
        audio.EOSCallback = alexa.EOSCallback
        audio.PlaybackStartedCallback = alexa.PlaybackStartedCallback
        audio.RecognizeCallback = alexa.Recognize

        #audio.Listen(5000)
        #return
        for sentence in (
                "set a timer for 30 seconds",
                "set an alarm for 2pm tomorrow",                
                "what is my flash news?",
                "decrease volume",
                "decrease volume",
                "decrease volume",
                "decrease volume",
                "increase volume",
                "increase volume",
        ):
            audiofp = audio.TTS(sentence)

            # used for diagnostics
            class streamedfile:
                def __init__(self, content):
                    self._content = content
                    self._length = len(content.getvalue())
                    self._offset = 0
    
                def read(self, length=None):
                    #log.info("Offset %s length %s, want %s", self._offset, self._length, length)
                    if self._offset == self._length:
                        return ''
                    block = self._content.read(length)
                    self._offset = self._offset + len(block)
                    return block

                def close(self):
                    log.info("Closing streamedfile")

            #alexa.Recognize(streamedfile(audiofp))
            alexa.Recognize(audiofp)            
            time.sleep(4)
        
    t = threading.Thread(target=alexa_thread, daemon=True)
    t.start()

    GObject.MainLoop().run()
