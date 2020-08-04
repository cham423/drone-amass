# Overview
This is a [lair](https://github.com/lair-framework) drone for importing json output from [Amass](https://github.com/OWASP/Amass) into a lair project.

# Usage
```
  drone-amass [options] <id> <filename>
  export LAIR_ID=<id>; drone-amass [options] <filename>
Options:
  -version			show version and exit
  -verbose			enable verbose output
  -h              show usage and exit
  -k              allow insecure SSL connections
  -tags           a comma separated list of tags to add to every host that is imported
  -force-hosts    import all hosts into Lair, default behaviour is to only import
                  hostnames for hosts that already exist in a project
  -force-ports    disable data protection in the API server for excessive ports
  -safe-netblocks	disable adding all netblock results from amass, and instead only add netblocks
					that were already present in the lair project.
```

# Bugs
- the sessing setup is buggy at times, and sometimes the tool will have to be executed multiple times to get a successful import
- imports will not work if you don't have at least one netblock and/or host added before you run this program
- if force-hosts is given, host will be imported with the green status