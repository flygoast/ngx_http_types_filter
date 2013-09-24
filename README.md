# ngx_http_types_filter_module

## Introduction

The `ngx_http_types_filter` module can be used to change the `Content-Type`
output header depending on an extension variable and a optional condition 
variable. If the condition variable value is `1`, then parse extension from the 
extension variable, use this extension instead of uri's extension to determine
the `Content-Type` output header.

## Synopsis

    location / {
        ...
        types_filter $arg_fname $condition;
        types_filter_use_default on;
    }

## Directives

* **syntax**: ***types_filter*** <$extension> [$condition]
* **default**: --
* **context**: http, server, location, location if
    
If a condition variable specified, the module will only change the 
`Content-Type` output header depending on the extension variable when the
variable value is `1`. The last '.' leading part but without '/' before the '.'
in the extension variable value is parsed as the extension name.

* **syntax**: ***types_filter_use_default***  on|off
* **default**: on
* **context**: http, server, location, location if

If the flag was set to off, when no extension name found in extension variable,
or didn't find the type in types of the location, the module would not use the
default type of the location. 

## Installation

    cd nginx-*version*
    ./configure --add-module=/path/to/this/directory
    make
    make install

## Status

This module is compatible with following nginx releases:
- 1.2.6
- 1.2.7

## Author

FengGu <flygoast@126.com>
