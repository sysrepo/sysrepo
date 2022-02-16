Name: sysrepo
Version: {{ version }}
Release: {{ release }}%{?dist}
Summary: YANG-based configuration and operational data store
Url: https://github.com/sysrepo/sysrepo
Source: sysrepo-%{version}.tar.gz
License: BSD

BuildRequires:  cmake
BuildRequires:  gcc
BuildRequires:  gcc-c++
BuildRequires:  make
BuildRequires:  pkgconfig(libyang) >= 2.0.7
BuildRequires:  systemd

%package devel
Summary:   Development files for sysrepo
Requires:  %{name}%{?_isa} = %{version}-%{release}

%package tools
Summary:   sysrepo executable tools
Requires:  %{name}%{?_isa} = %{version}-%{release}

%description devel
Headers of sysrepo library.

%description tools
Executable tools for sysrepo.

%description
YANG-based configuration and operational data store - runtime Applications can
use sysrepo to store their configuration modeled by provided YANG model
instead of using e.g. flat configuration files. Sysrepo will ensure data
consistency of the data stored in the data store and enforce data constraints
defined by YANG model.

The library is implemented in C and provides an API for other software
to use for accessing sysrepo datastore.

%prep
%autosetup -p1
mkdir build

%build
cd build
cmake \
    -DCMAKE_INSTALL_PREFIX:PATH=%{_prefix} \
    -DCMAKE_BUILD_TYPE:String="Release" \
    -DCMAKE_C_FLAGS="${RPM_OPT_FLAGS}" \
    -DCMAKE_CXX_FLAGS="${RPM_OPT_FLAGS}" \
    ..
make

%install
cd build
make DESTDIR=%{buildroot} install

%postun
rm -rf /dev/shm/sr_*
rm -rf /dev/shm/srsub_*
rm -rf /etc/sysrepo/

%files
%license LICENSE
%{_libdir}/libsysrepo.so.7
%{_libdir}/libsysrepo.so.7.*

%files tools
%{_bindir}/sysrepocfg
%{_bindir}/sysrepoctl
%{_bindir}/sysrepo-plugind
%{_datadir}/man/man1/sysrepocfg.1.gz
%{_datadir}/man/man1/sysrepoctl.1.gz
%{_datadir}/man/man8/sysrepo-plugind.8.gz
%{_unitdir}/sysrepo-plugind.service

%files devel
%{_libdir}/libsysrepo.so
%{_libdir}/pkgconfig/sysrepo.pc
%{_includedir}/sysrepo*.h
%{_includedir}/sysrepo/*.h
%dir %{_includedir}/sysrepo/

%changelog
* Mon Oct 11 2021 Jakub Ružička <jakub.ruzicka@nic.cz> - {{ version }}-{{ release }}
- upstream package
