[![Build Status](https://travis-ci.org/nirizr/rematch.svg?branch=master)](https://travis-ci.org/nirizr/rematch)

# rematch

REmatch, a simple binary diffing utility that just works. 

It is intended to be used by reverse engineers by revealing and identifying previously reverse engineered similar functions and migrate documentation and annotations to current IDB. It does that by locally collecting data about functions in your IDB and uploads that information to a web service (which you're supposed to set up as well). Upon request, the web service can match your functions against all (or part) of previously uploaded functions and provide matches.

A secondary goal of this (which is not currently pursued) is to allow synchronization between multiple reverse engineers working on the same file.

At least, we hope it will be. Rematch is still a work in progress and is not fully functional at the moment.
We're currently working on bringing up basic functionality. Check us out again soon, or watch for updates!

# Goal of REmatch

The goal of REmatch is to act as a maintained, extendable, open source tool for advanced assembly function-level binary comparison and matching. Hopefully, this will be a completely open source and free (as in speech) community-driven tool.

We've noticed that although there are more than several existing binary matching tools, there's no one tool that provides all of the following:

1. Open source and community driven.
2. Supports advanced matching algorithms (ML included ™).
3. Fully integrated into IDA.
4. Allows managing multiple projects in a single location.
5. Enables out of the box one vs. many matches.
6. Actively maintained.

# Current state (30th of August, 2016)

Development advances on a daily basis. We have a basic server and an IDA plugin. We collect a few relatively simple features and working on adding more. We have a matching stab that we will populate soon. Features are uploaded to the server. Basic plugin settings, project hierarchy and user authentication. We have a skeleton for the match results dialog (which supports some basic python scripting! :D).
