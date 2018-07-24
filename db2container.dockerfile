##################################################################
# IBM Confidential
#
# OCO Source Materials
#
# WebSphere Commerce
#
# (C) Copyright IBM Corp. 2016
#
# The source code for this program is not published or otherwise
# divested of its trade secrets, irrespective of what has
# been deposited with the U.S. Copyright Office.
##################################################################

## Part A: Define the base operating system
# Dockerfile will create a base DB2 image
# Using base image of CentOS latest
FROM /library/centos:latest


## Part B Setup the environment with Libraries and set permissions to directories and 
## Adding dbadmin user and wcs user
RUN yum install -y \
    pam \
    pam.i686 \
    ncurses-libs.i686 \
    file \
    libaio \
    libstdc++-devel.i686 && \
    yum clean all && \
    useradd -ms /bin/bash db2inst1 && \
    groupadd wcs && \
    useradd -g wcs wcs && \
    echo -e "wcs1\nwcs1\n" | passwd wcs

# Part C # Environment variables are needed by the base DB2 Express image 
# Specify a password for use db2inst1 

ENV DB2INST1_PASSWORD passw0rd 
ENV PATH /SETUP/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin 
ENV LD_LIBRARY_PATH /home/db2inst1/sqllib/lib64:/home/db2inst1/sqllib/lib64/gskit:/home/db2inst1/sqllib/lib32 

# Part D 
COPY SETUP /SETUP/ 

# Part E, Extract, run the setup file, add license and delete the temporary files 
RUN mkdir /SETUP/tmp/DB2INSTALLER && \
    curl -o /SETUP/tmp/DB2INSTALLER/DB2INSTALLER.tgz http://<library repository>/DB2/db2-wse-11.1.2.2.gz && \
    tar -xzf /SETUP/tmp/DB2INSTALLER/DB2INSTALLER.tgz -C /SETUP/tmp/DB2INSTALLER/ && \
    /SETUP/tmp/DB2INSTALLER/server_r/db2setup -r /SETUP/tmp/db2server.rsp && \
    /bin/su -c "db2licm -a /SETUP/tmp/DB2INSTALLER/server_r/db2/license/db2wse_o.lic" - db2inst1 && \
    /bin/su -c "db2licm -a /SETUP/tmp/DB2INSTALLER/server_r/db2/license/db2ef.lic" - db2inst1 && \
    chmod +x /SETUP/bin/* && \
    rm -r /SETUP/tmp


# Part F 
#Start the DB2 server and print out the diag log 
ENTRYPOINT ["/bin/bash","/SETUP/bin/entrypoint.sh" ] 
CMD [ "start" ] 

# Part G # DB2 instance port 
EXPOSE 50000 50001 