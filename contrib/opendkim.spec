# $Id: opendkim.spec,v 1.1 2009/08/13 08:54:09 mmarkley Exp $

Summary: Open-source DKIM milter
Name: opendkim
Version: 1.0.0
Release: 1
License: BSD
Group: Mail
Requires: libopendkim
Source: opendkim-%{version}.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}-root
Prefix: %{_prefix}

%description
An open source milter for providing DKIM service

%package -n libopendkim
Summary: Open source DKIM library
Group: Mail

%description -n libopendkim
A C library for producing DKIM-aware applications

%package -n libopendkim-devel
Summary: Open source DKIM library development files
Group: Development/Libraries
Requires: libopendkim

%description -n libopendkim-devel
Header files for development with libopendkim

%prep
%setup

%build
# Required for proper OpenSSL support on some versions of RedHat
if [ -d /usr/include/kerberos ]; then
	INCLUDES="$INCLUDES -I/usr/include/kerberos"
fi
./configure --prefix=%{_prefix} --libdir=%{_libdir} --mandir=\${prefix}/share/man CPPFLAGS="$INCLUDES"

make

%install
make install DESTDIR="$RPM_BUILD_ROOT"
mkdir -p "$RPM_BUILD_ROOT"/etc
mkdir -p "$RPM_BUILD_ROOT"/etc/init.d
install -m 0755 contrib/opendkim.init "$RPM_BUILD_ROOT"/etc/init.d/opendkim
echo '# Basic OpenDKIM config file
# See opendkim.conf(5) or /usr/share/doc/opendkim/opendkim.conf.sample for more
Mode	v
Syslog	yes
Socket	local:/var/run/opendkim/opendkim.socket' > "$RPM_BUILD_ROOT"/etc/opendkim.conf

%post
if ! id -u opendkim >/dev/null 2>&1; then
	useradd -M -d /var/lib -r -s /bin/false opendkim
	if [ "$(id -gn opendkim)" != "opendkim" ]; then
		groupadd opendkim
		usermod -g opendkim opendkim
	fi
fi
mkdir /var/run/opendkim
chown opendkim:opendkim /var/run/opendkim
if [ -x /sbin/chkconfig ]; then
	/sbin/chkconfig --add opendkim
elif [ -x /usr/lib/lsb/install_initd ]; then
	/usr/lib/lsb/install_initd opendkim
fi

%postun
service opendkim stop && rm -f /var/run/opendkim/opendkim.sock && rmdir /var/run/opendkim 2>/dev/null
if [ -x /sbin/chkconfig ]; then
	/sbin/chkconfig --del opendkim
elif [ -x /usr/lib/lsb/remove_initd ]; then
	/usr/lib/lsb/remove_initd opendkim
fi
userdel opendkim
if [ "$(id -gn opendkim)" = "opendkim" ]; then
	groupdel opendkim
fi

%clean
if [ "$RPM_BUILD_ROOT" != "/" ]; then
	rm -r "$RPM_BUILD_ROOT"
fi

%files
%defattr(-,root,root)
%doc docs FEATURES KNOWNBUGS LICENSE LICENSE.Sendmail README RELEASE_NOTES RELEASE_NOTES.Sendmail
%config /etc/opendkim.conf
/etc/init.d/opendkim
%{_prefix}/sbin
%{_prefix}/share/doc
%{_prefix}/share/man/man5
%{_prefix}/share/man/man8

%files -n libopendkim
%defattr(-,root,root)
%doc docs FEATURES KNOWNBUGS LICENSE LICENSE.Sendmail README RELEASE_NOTES RELEASE_NOTES.Sendmail
%{_libdir}/libopendkim.so.*

%files -n libopendkim-devel
%defattr(-,root,root)
%doc docs FEATURES KNOWNBUGS LICENSE LICENSE.Sendmail README RELEASE_NOTES RELEASE_NOTES.Sendmail
%{_prefix}/include
%{_libdir}/*.a
%{_libdir}/*.la
%{_libdir}/*.so
%{_prefix}/share/man/man3
%{_prefix}/share/opendkim

