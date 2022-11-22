# TS CLI
A command line client for the Threat Stack API. Made in Go, with love.

FYI: This is a work in progress. We released it a bit earlier than we may
normally have to get it in folks hands. If you run into issues, please open
an issue or provide a PR. Thanks!

## Building the TS CLI
If you have an existing Go environment set up, skip ahead to "Get the
Source and Build the TS CLI."

### Setting Up a Go Environment
Fortunately, setting up Go isn't too bad these days. Go has some preferences
on where code lives on the filesystem; there's a directory structure under
$GOPATH that you'll need. To install and set $GOPATH, run:

1. brew install golang
2. export GOPATH=$HOME/go
3. mkdir -p $GOPATH/bin $GOPATH/src $GOPATH/pkg
4. export PATH=$GOPATH/bin:$PATH

Add the exports to your shell profile (.zshrc, .bash_profile), and you should
be good to go.

### Build the TS CLI
You can build and put the `ts` binary in your $PATH by running:

```
go get github.com/threatstack/ts
```

## Configuring the TS CLI
Set the following environment variables before using any of the commands. You can
also set them on the command line (see `ts help`). 

These values for these variables can be found in the Threat Stack application under 
the Settings page. Once you're there, browse to the Application Keys tab, and they'll
show up.

| Environment Variable   | Purpose                                                       |
|------------------------|---------------------------------------------------------------|
| **TS_API_ENDPOINT**    | Defaults to `https://app.threatstack.com` - no trailing slash |
| **TS_API_KEY**         | Your API key                                                  |
| **TS_ORGANIZATION_ID** | ID of Organization you are making requests for                |
| **TS_USER_ID**         | ID of your user (_not_ email address - check UI)              |

## Using the TS CLI
The CLI isn't feature complete. As of today, you can retrieve information on agents 
and data portability enrollments.

### Agent Information
Retrieve a JSON object of all online agents in your organization using the 
`ts agent list online` command. Offline agents are available with the
`ts agent list offline` command. Retrieving information on a single agent is easy:
run the `ts agent show ID` command, where `ID` is the Agent ID. The Agent ID 
will likely be a UUID, but if it has been around for a while, it will be a 
24-character string.

`jq` is the easiest way to format the output.

### Portability Information
A human-friendly listing of your S3 exports is available with `ts portability s3 list`.

Add an S3 export to your organization with `ts portability s3 create`. There are flags, 
so it is best to run `ts portability s3 create --help`.

Delete exports with `ts portability s3 delete [S3 Bucket Name Here]`. 

### Raw mode
We realize that we're lacking some support for some endpoints, so we provide the ability
to send raw commands to the API. Use `ts raw --help`.

## Contributing
Before you start contributing to any project sponsored by F5, Inc. (F5) on GitHub, you will need to sign a Contributor License Agreement (CLA). This document can be provided to you once you submit a GitHub issue that you contemplate contributing code to, or after you issue a pull request.

If you are signing as an individual, we recommend that you talk to your employer (if applicable) before signing the CLA since some employment agreements may have restrictions on your contributions to other projects. Otherwise by submitting a CLA you represent that you are legally entitled to grant the licenses recited therein.

If your employer has rights to intellectual property that you create, such as your contributions, you represent that you have received permission to make contributions on behalf of that employer, that your employer has waived such rights for your contributions, or that your employer has executed a separate CLA with F5.

If you are signing on behalf of a company, you represent that you are legally entitled to grant the license recited therein. You represent further that each employee of the entity that submits contributions is authorized to submit such contributions on behalf of the entity pursuant to the CLA.