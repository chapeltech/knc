Name:           knc
Version:        1.12
Release:        2%{?dist}
Summary:        Kerberised NetCat
License:        MIT
URL:            https://github.com/elric1/knc
Source0:        knc-%{version}.tar.gz

BuildRequires:  autoconf
BuildRequires:  automake
BuildRequires:  gcc
BuildRequires:  krb5-devel
BuildRequires:  libtool
BuildRequires:  make
BuildRequires:  patchelf

Requires:       krb5-libs
Requires:       libknc%{?_isa} = %{version}-%{release}

%description
knc is a Kerberos-authenticated NetCat implementation.

%package -n libknc
Summary:        Runtime library for knc
Requires:       krb5-libs

%description -n libknc
The libknc package contains the shared library used by knc clients.

%package -n libknc-devel
Summary:        Development files for libknc
Requires:       libknc%{?_isa} = %{version}-%{release}

%description -n libknc-devel
The libknc-devel package contains headers and linker files for libknc.

%prep
%autosetup
sed -i 's/^SUBDIRS.*/SUBDIRS = bin lib/' Makefile.am

%build
autoreconf -fi
%configure --with-gss-dir=/usr
%make_build

%install
%make_install
find %{buildroot} -name '*.la' -delete
find %{buildroot} -name '*.a' -delete
find %{buildroot} -type f -print0 | while IFS= read -r -d '' file; do
    if file "$file" | grep -q 'ELF'; then
        patchelf --remove-rpath "$file" 2>/dev/null || true
    fi
done

%post -n libknc -p /sbin/ldconfig
%postun -n libknc -p /sbin/ldconfig

%files
%license debian/copyright
%{_bindir}/knc
%{_mandir}/man1/knc.1*

%files -n libknc
%license debian/copyright
%{_libdir}/libknc.so.0*

%files -n libknc-devel
%license debian/copyright
%{_includedir}/libknc.h
%{_libdir}/libknc.so
%{_mandir}/man3/libknc.3*

%changelog
* Wed Aug 05 2026 ChapelTech <packages@chapel.tech> - 1.12-2
- Build against the Rocky MIT Kerberos implementation.

* Thu Apr 30 2026 ChapelTech <packages@chapel.tech> - 1.12-1
- Add Rocky/RHEL packaging.
