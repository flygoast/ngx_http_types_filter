# ngx_http_types_filter_module

## Introduction

The `ngx_http_types_filter` module can be used to change the `Content-Type`
output header according to the condition specified in `if` clause.
If true, it would parse extension from the extension variable, use this extension instead of uri's extension to determine the `Content-Type` output header.
If there was no `if` clause, this would be done unconditionally.

## Synopsis

    location / {
        ...
        types_filter $arg_fname if ($condition);
        types_filter $arg_fname;
        types_filter_use_default on;
    }

## Directives

* **syntax**: ***types_filter*** <$extension> [if ($condition)]
* **default**: --
* **context**: http, server, location
    
If an `if` clause supplied, the module will only change the `Content-Type` output header depending on the extension variable when the evaluation of the clause is true. If there was no `if` clause, this would be done unconditionally. The condition was checked in the order of their appearance in the configuration file. Only the type process in first condition matched would be done. The last '.' leading part but without '/' before the '.' in the extension variable value is parsed as the extension name. 

* **syntax**: ***types_filter_use_default***  on|off
* **default**: on
* **context**: http, server, location

If the flag was set to off, when no extension name found in extension variable,
or didn't find the type in types of the location, the module would not use the
default type of the location, just skip this header filter module.

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
