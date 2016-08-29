# python-alexa-client

Experimental Python implementation of an
[Alexa Voice Service](https://developer.amazon.com/alexa-voice-service)
client.

I use this as one component of a home-grown Raspberry Pi radio, which
has the following features:

* [Flic](https://flic.io/) support
* [PiGlow](https://shop.pimoroni.com/products/piglow) support
* Podcast playing
* Streaming music playing
* Alexa Voice Service integration
* Text to speech from [IVONA](https://www.ivona.com/)

The Alexa Voice Service component is provided by the python libraries
in this repository.

It's certainly not ready for anyone else to just pick up and use, but
I wanted to get it out there as I didn't find any other
implementations.

## Development status

Very very early - mostly this is experiments to try to understand the
documentation.

## Features

* Streaming voice to AVS
* Supports most AVS features, including alarms, alerts, listen
directives and so on

## Use

See the bottom of `alexa.py` - you can try running `alexa.py` for a
simple demo, which uses a local text-to-speech system rather than your
microphone to generate voice requests.

You'll need a `tokens.json`, which you can probably get with the help
of `get-aws-token.py` - edit and fill in the `FILLMEIN` parts. (Or
better, make it ask for those elements and send in a pull request!)

You'll need to configure the `redirect_uri` in your app in the AVS dev
site to `http://localhost:3000/authresponse`.

## Requirements

This list is _more_ than what is needed - it's from my Ansible
playbook for installing my overall Raspberry Pi radio system.

Raspbian packages:

 * git
 * python3-smbus
 * python3-requests
 * python3-gst-1.0
 * python3-numpy
 * python3-flask
 * python3-sh
 * python3-requests
 * python3-gi
 * python3-pip
 * python3-feedparser
 * python3-rpi.gpio
 * gir1.2-gst-plugins-base-1.0
 * gir1.2-gstreamer-1.0
 * gstreamer1.0-tools
 * gstreamer1.0-plugins-ugly
 * gstreamer1.0-plugins-good
 * gstreamer1.0-alsa
 * gstreamer1.0-libav
 * libasound2-dev
 * i2c-tools
 * python3-dateutil
 * python3-tz
 * python3-sqlalchemy
	
From PyPi (e.g., install with `pip3`):

 * flask_restful
 * colormath
 * evdev
 * pyalsaaudio
 * pyudev
 * requests_toolbelt
 * hyper
 * shove
 * setuptools
