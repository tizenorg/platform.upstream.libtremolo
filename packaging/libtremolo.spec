Name:       libtremolo
Summary:    Audio Library
Version:    0.0.11
Release:    1
Group:      System/Libraries
License:    BSD-2.0 and Apache-2.0
Source0:    %{name}-%{version}.tar.gz
Requires(post):  /sbin/ldconfig
Requires(postun):  /sbin/ldconfig

%ifarch armv7el armv7l
BuildRequires: pkgconfig(glib-2.0)
BuildRequires: pkgconfig(mm-common)
BuildRequires: pkgconfig(mm-log)
%endif

BuildRoot:  %{_tmppath}/%{name}-%{version}-build

%description
Tremolo is playback codec, which is an arm optimized version of the ogg vorvis 'Tremor'

%package devel
Summary:    Multimedia Framework Utility Library (DEV)
Group:      Development/Libraries
Requires:   %{name} = %{version}-%{release}

%description devel
Tremolo is playback codec, which is an arm optimized version of the ogg vorvis 'Tremor'(DEV)

%prep
%setup -q

%build
./autogen.sh

CFLAGS="$CFLAGS -DEXPORT_API=\"__attribute__((visibility(\\\"default\\\")))\" -D_MM_PROJECT_FLOATER" \
LDFLAGS+="-Wl,--rpath=%{_libdir} -Wl,--hash-style=both -Wl,--as-needed" \
%configure --prefix=%{_prefix}

make %{?jobs:-j%jobs}

sed -i -e "s#@TREMOLO_REQPKG@#$TREMOLO_REQPKG#g" tremolo/libtremolo.pc

%install
rm -rf %{buildroot}
%make_install

%clean
rm -rf %{buildroot}

%post -p /sbin/ldconfig
%postun -p /sbin/ldconfig


%files
%manifest libtremolo.manifest
%defattr(-,root,root,-)
%{_libdir}/*.so*
%license COPYING LICENSE.APLv2

%files devel
%defattr(-,root,root,-)
%{_includedir}/*
%{_libdir}/pkgconfig/*
