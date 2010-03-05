# $Id: opendkim.spec,v 1.3 2010/03/05 06:17:09 mmarkley Exp $

Summary: An open source milter for providing DKIM service
Name: opendkim
Version: 2.0.0
Release: 1
License: BSD
Group: System Environment/Daemons
Requires: libopendkim
BuildRequires: sendmail-devel, openssl-devel
Source: opendkim-%{version}.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}-root
Prefix: %{_prefix}

%description
The OpenDKIM Project is a community effort to develop and maintain a C library
for producing DKIM-aware applications and an open source milter for providing
DKIM service.

%package -n libopendkim
Summary: An open source DKIM library
Group: System Environment/Libraries

%description -n libopendkim
This package contains the library files required for running services built
using libopendkim.

%package -n libopendkim-devel
Summary: Development files for libopendkim
Group: Development/Libraries
Requires: libopendkim

%description -n libopendkim-devel
This package contains the static libraries, headers, and other support files
required for developing applications against libopendkim.

%prep
%setup

%build
# Required for proper OpenSSL support on some versions of RedHat
if [ -d /usr/include/kerberos ]; then
	INCLUDES="$INCLUDES -I/usr/include/kerberos"
fi
./configure --prefix=%{_prefix} --libdir=%{_libdir} --mandir=%{_mandir} CPPFLAGS="$INCLUDES"

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
mkdir -p "$RPM_BUILD_ROOT"/%{_docdir}/opendkim-%{version}/examples
cp opendkim/*.sample "$RPM_BUILD_ROOT"/%{_docdir}/opendkim-%{version}/examples/
cp opendkim/README "$RPM_BUILD_ROOT"/%{_docdir}/opendkim-%{version}/README.opendkim
cp -r docs FEATURES KNOWNBUGS LICENSE LICENSE.Sendmail README RELEASE_NOTES RELEASE_NOTES.Sendmail contrib/ "$RPM_BUILD_ROOT"/%{_docdir}/opendkim-%{version}/
rm -r "$RPM_BUILD_ROOT"/%{_prefix}/share/doc/opendkim

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
%doc %{_docdir}/opendkim-%{version}
#%doc docs FEATURES KNOWNBUGS LICENSE LICENSE.Sendmail README RELEASE_NOTES RELEASE_NOTES.Sendmail contrib/
#%doc %{_docdir}/opendkim-%{version}/examples
#%doc %{_docdir}/opendkim-%{version}/README.opendkim
#%doc %{_prefix}/share/doc/opendkim
%config /etc/opendkim.conf
%config /etc/init.d/opendkim
#%{_defaultdocdir}/opendkim-%{version}-%{release}/examples
%{_prefix}/sbin
%{_mandir}

%files -n libopendkim
%defattr(-,root,root)
%doc docs KNOWNBUGS LICENSE LICENSE.Sendmail README RELEASE_NOTES RELEASE_NOTES.Sendmail
%{_libdir}/libopendkim.so.*

%files -n libopendkim-devel
%defattr(-,root,root)
%doc docs LICENSE LICENSE.Sendmail libopendkim/docs/*.html
%{_prefix}/include
%{_libdir}/*.a
%{_libdir}/*.la
%{_libdir}/*.so
%{_libdir}/pkgconfig

