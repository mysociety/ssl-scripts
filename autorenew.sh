#!/bin/bash

if [ "$UID" != "0" ]; then
    echo "This script is intended to be run as root, from cron."
    exit 1
fi

START_DIR=/data/vhost/acme-challenge.mysociety.org/ssl-scripts
LOGFILE="/var/log/letsencrypt/autorenew.log"
ERROR_COUNT=0
ERROR_CERTS=
WEEKS=2
CERT_DIR=/data/letsencrypt/certificates
PUPPET_DIR=/data/puppet/site/profiles/files/certificates/etc/ssl/mysociety

cd $START_DIR

echo "$( date "+%b %d %T" ) Staring SSL certificate autorenew run" >>$LOGFILE

while read renewal; do
    certificate=$( echo $renewal | cut -d, -f1 )
    cert_file=$(  echo $renewal | cut -d, -f2 )
    echo "Checking $certificate against the Staging CA" >>$LOGFILE
    sudo -u letsencrypt -i letsencrypt $certificate --live-run --staging-ca >>$LOGFILE 2>&1
    STAGING_EXIT=$?
    if [ "$STAGING_EXIT" != "0" ]; then
        echo "Problem running $certificate through the Staging CA. Skipping for production." >>$LOGFILE
        (( ERROR_COUNT++ ))
        ERROR_CERTS="$certificate (staging); $ERROR_CERTS"
    else
        echo "Success. Now attempting to renew $certificate" >>$LOGFILE
        sudo -u letsencrypt -i letsencrypt $certificate --live-run --prod-ca >>$LOGFILE 2>&1
        PROD_EXIT=$?
        if [ "$PROD_EXIT" != "0" ]; then
            echo "Problem running $certificate through the Production CA." >>$LOGFILE
            (( ERROR_COUNT++ ))
            ERROR_CERTS="$certificate (production); $ERROR_CERTS"
        else
            # Copy certificates into the right place, commit, etc.
            cd /data/puppet
            git checkout --quiet ssl_renewals
            git fetch --quiet
            git rebase --quiet origin/master
            mv $CERT_DIR/*${cert_file}.crt $PUPPET_DIR/certs/
            mv $CERT_DIR/*${cert_file}.key $PUPPET_DIR/keys
            chown -R :privatecvs $PUPPET_DIR/
            chmod 0664 $PUPPET_DIR/certs/*
            chmod 0660 $PUPPET_DIR/keys/*
            git add $PUPPET_DIR/*
            git commit --quiet -m "SSL: auto-renewed $certificate"
            git push --quiet origin ssl_renewals 2>/dev/null
            git checkout --quiet master
            cd $START_DIR
        fi
    fi
done < <( $START_DIR/renew.py --list --weeks=$WEEKS )

echo "$( date "+%b %d %T" ) Ending SSL certificate autorenew run" >>$LOGFILE

if [ "$ERROR_COUNT" != "0" ]; then
    echo "The SSL certificate renewal script encountered $ERROR_COUNT errors:"
    echo $ERROR_CERTS
fi

exit $ERROR_COUNT
