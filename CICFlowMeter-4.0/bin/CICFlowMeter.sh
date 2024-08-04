#!/bin/bash

# Check if JAVA_HOME is set
if [ -z "$JAVA_HOME" ]; then
    JAVA_EXE=$(which java)
    if [ $? -ne 0 ]; then
        echo "ERROR: JAVA_HOME is not set and no 'java' command could be found in your PATH."
        echo "Please set the JAVA_HOME variable in your environment to match the location of your Java installation."
        exit 1
    fi
else
    JAVA_EXE="$JAVA_HOME/bin/java"
    if [ ! -x "$JAVA_EXE" ]; then
        echo "ERROR: JAVA_HOME is set to an invalid directory: $JAVA_HOME"
        echo "Please set the JAVA_HOME variable in your environment to match the location of your Java installation."
        exit 1
    fi
fi

# Set application home directory
DIRNAME=$(dirname "$0")
APP_HOME="$DIRNAME/.."

# Set classpath
CLASSPATH="$APP_HOME/lib/commons-io-2.5.jar:$APP_HOME/lib/log4j-core-2.11.0.jar:$APP_HOME/lib/slf4j-api-1.7.25.jar:$APP_HOME/lib/jsr305-1.3.9.jar:$APP_HOME/lib/commons-lang3-3.6.jar:$APP_HOME/lib/commons-math3-3.5.jar:$APP_HOME/lib/checker-compat-qual-2.0.0.jar:$APP_HOME/lib/slf4j-log4j12-1.7.25.jar:$APP_HOME/lib/jfreechart-1.5.0.jar:$APP_HOME/lib/error_prone_annotations-2.1.3.jar:$APP_HOME/lib/hamcrest-core-1.3.jar:$APP_HOME/lib/j2objc-annotations-1.1.jar:$APP_HOME/lib/log4j-1.2.17.jar:$APP_HOME/lib/jnetpcap-1.4.1.jar:$APP_HOME/lib/guava-23.6-jre.jar:$APP_HOME/lib/log4j-api-2.11.0.jar:$APP_HOME/lib/animal-sniffer-annotations-1.14.jar:$APP_HOME/lib/tika-core-1.17.jar:$APP_HOME/lib/CICFlowMeter-4.0.jar:$APP_HOME/lib/weka-stable-3.6.14.jar:$APP_HOME/lib/junit-4.12.jar:$APP_HOME/lib/java-cup-0.11a.jar"

# Default JVM options
DEFAULT_JVM_OPTS="-Djava.library.path=$APP_HOME/lib/native"

# Execute CICFlowMeter
"$JAVA_EXE" $DEFAULT_JVM_OPTS $JAVA_OPTS $CIC_FLOW_METER_OPTS -classpath "$CLASSPATH" cic.cs.unb.ca.ifm.App "$@"

# Capture exit status
exit_status=$?
if [ $exit_status -ne 0 ]; then
    exit 1
fi
