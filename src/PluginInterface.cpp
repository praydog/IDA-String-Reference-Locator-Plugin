#include <idp.hpp>
#include <loader.hpp>

#include "Plugin.hpp"

// Interface to IDA.
plugin_t PLUGIN
{
    IDP_INTERFACE_VERSION,

    plugin.flags,

    // lambdas let us use class objects to do this instead of C-style standalone/static functions.
    []() { return plugin.OnInit(); },
    []() { return plugin.OnTerminate(); },
    [](int arg) { return plugin.OnRun(arg); },

    plugin.comment,
    plugin.help,
    plugin.name,
    plugin.hotkey
};