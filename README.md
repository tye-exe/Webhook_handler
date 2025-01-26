# Webhook_handler

This is just a small webserver that listens and verifies post messages from github webhooks.
It then updates my web server to the latest version.

If you want to modify this to use yourself, you will need to modify the `Dockerfile` to ensure that the necessary
dependencies are present, and to put a bash script in `./scripts` (which will be run every time a webhook message is
received). 
Also, the environment variable "WEBHOOK_SECRET" will need to be set to the secret used by github to sign the webooks,
I would recommend using a ".env" file.
