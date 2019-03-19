#!/bin/bash
#Version : 2.4.1(logrotate added for more services)
#Last modified : 28 Nov 2018


EMAILID=abc@outlook.com
PASSWORD=abc1234
	
## SMTP Credentials
DATE=`date +"%d%b%y_%H%M%S"`
EPEL_REPO=epel
RHEL_REPO=rhel-6-server-rpms
RHEL_OPTIONAL_REPO=rhel-6-server-optional-rpms
LOG_PATH='/home/support'
[ ! -d $LOG_PATH ] && mkdir -p $LOG_PATH
LOG_FILE=$LOG_PATH/Hardining.log
[ -f $LOG_FILE ] && mv $LOG_FILE $LOG_FILE-$DATE

function testCase ()
{
	read -r -p "Shall we ignore the above error and continue the installation  [Y/N] : " input
	case $input in
		[yY][eE][sS]|[yY])
			echo -e "Skipping the error";;
		[nN][oO]|[nN])
			echo -e "\nDebug and Run the script again!"
			exit 1;;
		*)
			echo "Invalid input"
			testCase
			;;
	esac
}

try () 
{
	"$@" > /dev/null 2>&1
	if [ "$?" -ne "0" ]; then
		echo -e "Command failure: $@" >> $LOG_FILE
		echo -e "Command failure: $@"
		testCase
	fi
}

CONFIG_UPDATE ()
{
	CONFIG_NAME=`echo $@ | awk -F '=' '{print $1}'`
	CONFIG_FILE=`echo $@ | awk -F '|' '{print $2}'`
	CONFIG_ENTRY=`echo $@ | awk -F '|' '{print $1}'`
	CONFIG_COMMENT=`echo $@ | awk -F '|' '{print $3}'`
	LINE_NUMBER=`echo $@ | awk -F '|' '{print $4}'`
	if [ -f "$CONFIG_FILE" ]; then
		if [ `grep  "^$CONFIG_NAME" $CONFIG_FILE | wc -l`  -eq 0 ]; then
			if [ "$LINE_NUMBER" ]; then
				sed -i ""$LINE_NUMBER"i $CONFIG_ENTRY"  $CONFIG_FILE
				[ "$CONFIG_COMMENT" ] && sed -i ""$LINE_NUMBER"i # $CONFIG_COMMENT" $CONFIG_FILE
			else
				[ "$CONFIG_COMMENT" ] && echo -e "# $CONFIG_COMMENT\n$CONFIG_ENTRY" >> $CONFIG_FILE || echo -e "$CONFIG_ENTRY" >> $CONFIG_FILE
			fi
		else
			sed -i "s#^$CONFIG_NAME.*#$CONFIG_ENTRY#" $CONFIG_FILE
		fi
	else
		[ "$CONFIG_COMMENT" ] && echo -e "# $CONFIG_COMMENT\n$CONFIG_ENTRY" >> $CONFIG_FILE || echo -e "$CONFIG_ENTRY" >> $CONFIG_FILE
	fi
}

#-->Install wget and vim tools
echo -e "\n\n************************\nHardening script started\n************************\n"
echo -e "Vim editor and wget tool installation started..."
for input in wget vim
do
	try yum install  $input --skip-broken  -y  
done
#-->Install EPEL
echo -e "EPEL installation started..."
try yum localinstall epel-release-6-8.noarch.rpm -y 
try rm -f epel-release-6-8.noarch.rpm
try sed -i '6s/enabled=0/enabled=1/1' /etc/yum.repos.d/epel.repo

if [ `yum repolist|grep epel|wc -l` -ge "1" ]
then 
#-->Install basic linux packages and java
	echo -e "\nepel repo installed"
	echo -e "\nDosunix, java applications installation started..."	
	try yum install sshpass dos2unix lrzsz nawk gnumeric freeipmi lm_sensors --skip-broken --enablerepo=$EPEL_REPO -y 
	try yum install java-1.8.0-openjdk-devel --skip-broken --enablerepo=$RHEL_REPO --enablerepo=$EPEL_REPO -y 
	echo -e "\nDosunix & java applications installed"	
#-->Install apache
	echo -e "\nApache webserver installation started..."	
	try yum install httpd --skip-broken --disablerepo=$EPEL_REPO -y 
	try cp /etc/httpd/conf/httpd.conf /etc/httpd/conf/httpd.conf-$DATE
	try sed -i 's/ServerSignature On/ServerSignature Off/g' /etc/httpd/conf/httpd.conf
	try sed -i 's/ServerTokens OS/ServerTokens Prod/g' /etc/httpd/conf/httpd.conf
	try sed -i "s:AllowOverride None:AllowOverride All:g" /etc/httpd/conf/httpd.conf
	try sed -i "s:Options Indexes FollowSymLinks:Options -Indexes FollowSymLinks:g" /etc/httpd/conf/httpd.conf
	try /sbin/service httpd restart  
	try /sbin/chkconfig httpd on
	echo -e "\nApache 2.2 Installed and Configured"
	
	echo -e "\nPostfix installation started..."
#-->Install and configure  Postfix 
	MAILDIRECTORY=/etc/postfix
	CONFFILE=main.cf
	SMTPSERVER=outlook.office365.com

	try	yum install postfix -y  
	try yum install cyrus-sasl-plain -y  
	try cp $MAILDIRECTORY/$CONFFILE $MAILDIRECTORY/"$CONFFILE"_"$DATE"
	try sed -i 's/inet_protocols = all/inet_protocols = ipv4/g' $MAILDIRECTORY/$CONFFILE
	echo -e "## SMTP Configuration\nrelayhost = [$SMTPSERVER]:587\nsmtp_use_tls = yes\nsmtp_sasl_auth_enable = yes\nsmtp_sasl_password_maps = hash:/etc/postfix/sasl_passwd\nsmtp_tls_CAfile = /etc/ssl/certs/ca-bundle.crt\nsmtp_sasl_security_options = noanonymous\nsmtp_sasl_tls_security_options = noanonymous\n\n## Sender Address\nsender_canonical_classes = envelope_sender, header_sender\nsender_canonical_maps =  regexp:/etc/postfix/sender_canonical_maps\nsmtp_header_checks = regexp:/etc/postfix/header_check" >> $MAILDIRECTORY/$CONFFILE
	echo "[$SMTPSERVER]:587 $EMAILID:$PASSWORD" > $MAILDIRECTORY/sasl_passwd
	try postmap $MAILDIRECTORY/sasl_passwd
	chown root:postfix $MAILDIRECTORY/sasl_passwd $MAILDIRECTORY/sasl_passwd.db
	chmod 640 $MAILDIRECTORY/sasl_passwd
	echo "/.+/ $EMAILID" > $MAILDIRECTORY/sender_canonical_maps
	echo "/From:.*/ REPLACE From: $EMAILID" > $MAILDIRECTORY/header_check
	try chkconfig postfix on
	try /sbin/service postfix restart  
	echo -e "\nPostfix installed and configured"
#-->Install and configure Logwatch 
	echo -e "\nLogwatch implementation started..."
	try yum install logwatch --skip-broken -y 
	try sed -i 's/MailTo = root/MailTo = root@localhost/g' /usr/share/logwatch/default.conf/logwatch.conf
	try sed -i 's/MailFrom = Logwatch/MailFrom = root@localhost/g' /usr/share/logwatch/default.conf/logwatch.conf
	sed -i 's/Detail = Low/Detail = Med/g' /usr/share/logwatch/default.conf/logwatch.conf
	logwatch --detail Low --mailto root@localhost --service all --range today
	echo -e "\nLogwatch implemented"
#-->Install and configure FTP 
	echo -e "\nFTP Installations Started ..."
	try yum install vsftpd* ftp* --enablerepo=$RHEL_REPO --enablerepo=$EPEL_REPO -y 
	sed -i 's/anonymous_enable=YES/anonymous_enable=NO/g' /etc/vsftpd/vsftpd.conf
	CONFIG_UPDATE 'userlist_deny=NO|/etc/vsftpd/vsftpd.conf'
	CONFIG_UPDATE 'pasv_min_port=2121|/etc/vsftpd/vsftpd.conf'
	CONFIG_UPDATE 'pasv_max_port=2142|/etc/vsftpd/vsftpd.conf'
	CONFIG_UPDATE 'xferlog_file=/var/log/vsftpd.log|/etc/vsftpd/vsftpd.conf' 
	CONFIG_UPDATE 'data_connection_timeout=600|/etc/vsftpd/vsftpd.conf' 
	CONFIG_UPDATE 'dual_log_enable=YES|/etc/vsftpd/vsftpd.conf' 
	CONFIG_UPDATE 'ftp_username=nobody|/etc/vsftpd/vsftpd.conf'

	echo -e "\nConfiguring SELINUX for ftp...."
	try setsebool -P  ftp_home_dir=1
	try setsebool -P allow_ftpd_full_access=1
	try chkconfig vsftpd on
	try service vsftpd restart  
	echo -e "\nInstalled and configured FTP applications successfully"

	echo -e "\nGcc package installation started..."
	try yum install gcc-c++ --skip-broken --enablerepo=$RHEL_REPO --enablerepo=$EPEL_REPO -y 
	echo -e "\nGcc package installed"
#-->Security
	try cd /opt
	try wget -N $DOWNLOAD_URL/lsm-current.tar.gz 
	try tar xzf lsm-current.tar.gz
	lsm_dir=`ls -lh|grep drw|grep lsm|rev|cut -d ' ' -f1|rev`
	cd $lsm_dir
	./install.sh > /dev/null 2>&1
	rm -f lsm-current.tar.gz
	try sed -i 's/USER=\"root\"/USER="root@localhost.localdomain"/g' /usr/local/lsm/conf.lsm
	#echo '*/10 * * * * root /usr/local/sbin/lsm -c >> /dev/null 2>&1'>/etc/cron.d/lsm
	echo -e "\nLinux Security Module implemented"

	try sed -i '/tmpfs/d' /etc/fstab
	echo 'tmpfs     /dev/shm    tmpfs   defaults,nodev,nosuid,noexec     0 0'>>/etc/fstab
	try mount -o remount /dev/shm
	mount | grep tmpfs
	echo -e "\nTemporary filesystem secured(tmpfs)"
	setenforce 0
	try sed -i 's/SELINUX=enforcing/SELINUX=permissive/g' /etc/sysconfig/selinux
	echo -e "\nSELINUX protection changed into permissive mode"
	echo -e "\nEnsure the User accounts with empty password"
	cat /etc/shadow | awk -F: '($2==""){print $1}'
	echo -e "\nEnsure the local user accounts have root privileges"
	awk -F: '($3 == "0") {print}' /etc/passwd|grep -v root

	echo -e "\nDisabling the following unnecessary services"
	for input in cups rpcbind nfs nfslock
	do
		if [ -f /etc/init.d/$input ]; then
			chkconfig $input off && /etc/init.d/$input stop > /dev/null 2>&1
			echo "$input"
		fi
	done
	echo -e "\nInstalling malicious detection tool : rkhunter and chkrootkit "

	try yum install chkrootkit -y 
	chkrootkit | grep INFECTED
	try yum install rkhunter -y 
	rkhunter -c --sk 
	echo -e "\nInstalled malicious detection tool \nLog will store into /var/log/rkhunter/rkhunter.log"
	try sed -i 's/SINGLE=\/sbin\/sushell/SINGLE=\/sbin\/sulogin/g' /etc/sysconfig/init
	echo -e "\nEnabled password protection in Single User mode"
	echo -e "\nList of xinetd based services"
	chkconfig --list | awk '/xinetd based services/,/""/'
	CONFIG_UPDATE 'net.ipv4.conf.all.rp_filter = 1|/etc/sysctl.conf|Enable IP Spoofing Protection'
	CONFIG_UPDATE 'kernel.exec-shield=1|/etc/sysctl.conf|Turn on execshield'
	CONFIG_UPDATE 'kernel.randomize_va_space=1|/etc/sysctl.conf'
	CONFIG_UPDATE 'net.ipv4.conf.all.log_martians = 1|/etc/sysctl.conf|Enable Logging of Spoofed Packets, Source Routed Packets, Redirect Packets'
	try sysctl -p 
	echo -e "\nIP Spoofing protection enabled"

	CONFIG_UPDATE 'install ipv6 /bin/true|/etc/modprobe.d/blacklist.conf'
	CONFIG_UPDATE 'NETWORKING_IPV6=no|/etc/sysconfig/network'
	CONFIG_UPDATE 'IPV6INIT=no|/etc/sysconfig/network'
	echo -e "\nIPV6 Network protocol Disabled"

	echo "SUID and SGID Binaried that need to be verified"
	find / -path -prune -o -type f -perm +6000 -ls 

	echo -e "\nSystem accounts with login shells that need attention"
	cat /etc/passwd|grep /bin/bash
	cat /etc/passwd|grep /bin/sh

	try chmod 644 /etc/passwd /etc/group
	try chmod 000 /etc/shadow
	echo -e "\npasswd, group and shadow file permissions protected"

	try touch /etc/cron.allow
	echo "root" > /etc/cron.allow
	try chmod 600 /etc/cron.allow
	awk -F: '{print $1}' /etc/passwd | grep -v root > /etc/cron.deny
	try touch /etc/at.allow
	echo "root" > /etc/at.allow
	try chmod 600 /etc/at.allow
	awk -F: '{print $1}' /etc/passwd | grep -v root > /etc/at.deny
	echo -e "\ncron and at schedule jobs protected"

	try sed -i 's/enabled=1/enabled=0/g' /etc/yum.repos.d/epel.repo
	if [ `yum repolist|grep epel|wc -l` -ge "1" ];then echo "Unable to disable epel; do manually"; else echo "epel repository disabled";fi

	echo -e "\nPHP application installation started..."
	#try sed -i '636s/enabled = 0/enabled = 1/g' /etc/yum.repos.d/redhat.repo
	try yum install php php-mysql php-mcrypt php-mbstring php-cli php-common --skip-broken  --enablerepo=$RHEL_OPTIONAL_REPO --enablerepo=$EPEL_REPO -y 
	try yum install phpmyadmin --enablerepo=$RHEL_OPTIONAL_REPO --enablerepo=$EPEL_REPO -y 
	try sed -i 's/max_execution_time =.*/max_execution_time = 60/g' /etc/php.ini
	try sed -i 's/upload_max_filesize =.*/upload_max_filesize = 50M/g' /etc/php.ini
	try sed -i 's/post_max_size =.*/post_max_size = 50M/g' /etc/php.ini
	try sed -i '24s/Deny/Allow/g' /etc/httpd/conf.d/phpMyAdmin.conf
	try /sbin/service httpd restart  
	echo -e "\nPHP application installed and configured"

	echo -e "\nMysql application installation started..."
	try yum install mysql-server mysql --skip-broken -y 
	try /sbin/service mysqld restart  
	try /sbin/chkconfig mysqld on
	try chsh -s /sbin/nologin mysql  
	echo -e "\nMysql application installed"

	echo -e "\nWebmin application installation started..."
	cd /opt
	try wget $DOWNLOAD_URL/webmin-1.750-1.noarch.rpm  	
	try yum localinstall webmin-1.750-1.noarch.rpm --skip-broken -y  
	rm -f webmin-1.750-1.noarch.rpm
	echo -e "\nWebmin application installed"

	try yum install mediainfo* libcurl* glances rsync --enablerepo=$EPEL_REPO --skip-broken -y  
	echo -e "\nMediainfo curl glances rsync applications installed"
	try yum install openssh* --skip-broken -y  
	/sbin/service sshd restart  
	echo -e "\nssh upgraded successfully"

	try yum install tcpdump --enablerepo=$RHEL_REPO --skip-broken -y  
	echo -e "\nTcpdump installed  successfully"
	cd /opt
	try wget $DOWNLOAD_URL/MegaCli-8.07.07-1.noarch.rpm  
	try yum localinstall MegaCli-8.07.07-1.noarch.rpm --skip-broken -y 
	rm -f MegaCli-8.07.07-1.noarch.rpm 

	try yum install parted --skip-broken -y  

	echo "Installed MeagCli RAID tool"
	try mkdir /var/www/html/video
	try ln -s /ftp/tvn /var/www/html/video

	echo -e "/var/log/httpd/*log {\n\tdateext\n\tmaxage 30\n\tmissingok\n\tnotifempty\n\tsharedscripts\n\tdaily\n\tpostrotate\n\t/sbin/service httpd reload > /dev/null 2>/dev/null || true\n\tendscript\n\tcompress\n}" > /etc/logrotate.d/httpd1
	echo -e "/var/log/nginx/*log {\n\tcopytruncate\n\tcompress\n\tdaily\n\tdateext\n\tnotifempty\n\tmissingok\n\tmaxage 30\n\tsharedscripts\n\tcompress\n}" > /etc/logrotate.d/nginix
	echo -e "/opt/apache-tomcat-8.5.24/logs/catalina*.out {\n\tdateext\n\tmaxage 30\n\tmissingok\n\tnotifempty\n\tcopytruncate\n\tdaily\n\trotate 15\n\tcompress\n}" > /etc/logrotate.d/tomcat
	try /sbin/service crond restart  
	echo "Apache log rotate implemented"
	try /sbin/service httpd restart  
	echo -e "\nXFS rpm installation started..."
	cd /opt
	try wget $DOWNLOAD_URL/xfsprogs-3.1.1-16.el6.x86_64.rpm  
	try yum localinstall xfsprogs-3.1.1-16.el6.x86_64.rpm --skip-broken -y --enablerepo=$RHEL_REPO --enablerepo=$EPEL_REPO 
	rm -f xfsprogs-3.1.1-16.el6.x86_64.rpm  
	echo -e "\nXFS rpm installed successfully"
	try yum install p7zip zip unzip bc sysstat ntp* --enablerepo=$RHEL_OPTIONAL_REPO --enablerepo=$EPEL_REPO -y 
	try chkconfig ntpd on
	try service ntpd restart
	try /bin/mkdir -p /var/www/html/cron
	[ ! -f /var/www/html/cron/server_valid.php ] && echo -e '<?php\necho "YES";die;\n?>'

#-->Apache Tuning
	echo -e "Apache tuning started"
        HTTP_CONFIG='/etc/httpd/conf/httpd.conf'
        [ -f $HTTP_CONFIG ] && cp $HTTP_CONFIG $HTTP_CONFIG-$DATE
        TOTAL_RAM=`awk '/MemTotal/ {a=$2*0.0008;printf "%3.0f",a}' /proc/meminfo`
        MAX_CLIENT=`echo $TOTAL_RAM | awk '{a=$1/20;printf "%3.0f",a}' | sed 's/ //g'`
        START_SERVERS=`echo $MAX_CLIENT | awk '{a=$1*.03;printf "%3.0f",a}' | sed 's/ //g'`
        MIN_SPARE=`echo $MAX_CLIENT | awk '{a=$1*.02;printf "%3.0f",a}' | sed 's/ //g'`
        MAX_SPARE=`echo $MAX_CLIENT | awk '{a=$1*.08;printf "%3.0f",a}' | sed 's/ //g'`
#-->Apache prefork configuration
        PARAMETERS=(StartServers.$START_SERVERS MinSpareServers.$MIN_SPARE MaxSpareServers.$MAX_SPARE ServerLimit.$MAX_CLIENT MaxClients.$MAX_CLIENT MaxRequestsPerChild.10000)
        for parameter in ${PARAMETERS[@]}
        do
                input=`echo $parameter | awk -F '.' '{print $1}'`
                NEW_VALUE=`echo $parameter | awk -F '.' '{print $NF}'`
                sed -i "/<IfModule prefork.c>/,/$input/ s/$input.*/$input $NEW_VALUE/" $HTTP_CONFIG
        done
	echo -e "Apache tuning completed..."
#-->KeepAlive settings
	try sed -i 's/^KeepAlive Off/KeepAlive On/' $HTTP_CONFIG	
	try sed -i "s/^MaxKeepAliveRequests *..*/MaxKeepAliveRequests $START_SERVERS/g" $HTTP_CONFIG
	try sed -i 's/^KeepAliveTimeout *..*/KeepAliveTimeout 5/g' $HTTP_CONFIG
	echo -e "KeepAlive configrued..."
#-->gzip config
	echo -e "AddOutputFilter INCLUDES .shtml\nAddType text/html .shtml\nAddType application/x-httpd-php .php\nAddType application/x-httpd-php-source .p\n\nAddOutputFilterByType DEFLATE text/plain\nAddOutputFilterByType DEFLATE text/html\nAddOutputFilterByType DEFLATE text/xml\nAddOutputFilterByType DEFLATE application/json\nAddOutputFilterByType DEFLATE text/css\nAddOutputFilterByType DEFLATE application/xml\nAddOutputFilterByType DEFLATE application/xhtml+xml\nAddOutputFilterByType DEFLATE application/rss+xml\nAddOutputFilterByType DEFLATE application/javascript\nAddOutputFilterByType DEFLATE application/x-javascript\nAddOutputFilterByType DEFLATE font/otf\nAddOutputFilterByType DEFLATE font/ttf\n\n# Remove browser bugs (only needed for really old browsers)\nBrowserMatch ^Mozilla/4 gzip-only-text/html\nBrowserMatch ^Mozilla/4\.0[678] no-gzip" > /etc/httpd/conf.d/deflate.conf
	echo "BrowserMatch \bMSIE !no-gzip !gzip-only-text/html" >> /etc/httpd/conf.d/deflate.conf
	echo -e "\nHeader append Vary User-Agent" >> /etc/httpd/conf.d/deflate.conf
	MODULE_CHECK=`grep -v "^#" $HTTP_CONFIG | grep -o mod_deflate | wc -l`
	[ "$MODULE_CHECK" -eq "0" ] && echo "LoadModule deflate_module modules/mod_deflate.so" >> $HTTP_CONFIG
	echo -e "Gzip module enabled and configured..."
#-->php presistent
	echo -e "Php presistent OFF..."
	try sed -i 's/^mysql.allow_persistent = On/mysql.allow_persistent = Off/' /etc/php.ini
	try /etc/init.d/httpd restart 
#-->mysql max connections and slow_query_log
	CONFIG_UPDATE 'slow_query_log = 1|/etc/my.cnf|Enabling slow query|2'
	CONFIG_UPDATE 'slow_query_log_file = /var/lib/mysql/slow-query-new.log|/etc/my.cnf||4' 
#-->Set Max open file
	CONFIG_UPDATE 'fs.file-max=50000000|/etc/sysctl.conf|No of open files'
#-->Set Max read Value
	CONFIG_UPDATE 'net.core.wmem_max=12582912|/etc/sysctl.conf|Max wmem value'
#-->Set Max write Value
	CONFIG_UPDATE 'net.core.rmem_max=12582912|/etc/sysctl.conf|Max rmem value'
	echo -e "\n\n**************************************\nHardening script executed successfully\n**************************************\n"
	try rm -f /opt/ServerHardeningV1.sh
	try rm -f /opt/HardeningInput.txt
else 
	echo "epel repo not enabled "
fi


