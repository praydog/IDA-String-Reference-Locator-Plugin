#include <thread>
#include <algorithm>
#include <vector>

#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>

#include "Plugin.hpp"

#include "IDAStringList.hpp"

Plugin plugin;

Plugin::Plugin()
{

}

void Plugin::OnRun(int arg)
{
    if (arg == -1)
        PLUGIN.flags |= PLUGIN_UNL;

    msg("Stringref plugin ran.\n");

    std::vector<RefInfo> references;
    FillReferences(references);
    SortAndPrint(references);

    msg("Stringref plugin finished. Double click any of the addresses to go to them.\n");
}

int Plugin::OnInit()
{
	return PLUGIN_KEEP;
}

void Plugin::OnTerminate()
{

}

void Plugin::FillReferences(std::vector<RefInfo>& references)
{
    m_stringList.Populate();

    xrefblk_t xref;

    for (bool refFound = xref.first_to(get_screen_ea(), XREF_ALL); refFound; refFound = xref.next_to())
        OnXRef(&xref, references);
}

void Plugin::OnXRef(xrefblk_t* xref, std::vector<RefInfo>& references)
{
    auto xrefFlags = getFlags(xref->from);

    if (!isCode(xrefFlags))
        return;

    auto functionArea = funcs.get_area(xref->from);

    if (!functionArea)
        return;

    for (auto instruction = functionArea->startEA; instruction < functionArea->endEA; instruction += cmd.size)
    {
        // bail out (maybe some obfuscation will break this?)
        if (!decode_insn(instruction))
            break;

        for (const auto& op : cmd.Operands)
        {
            ea_t opcodeRef;

            // check op.addr if it's valid, and then op.value as the fallback
            for (opcodeRef = op.addr; opcodeRef != op.value; opcodeRef = op.value)
            {
                if (opcodeRef && isData(getFlags(opcodeRef)))
                    break;

                opcodeRef = 0;
            }

            if (!opcodeRef)
                continue;

            auto strInfo = m_stringList[opcodeRef];

            if (!strInfo || strInfo->type == -1)
                continue;

            xrefblk_t stringXref;

            if (stringXref.first_to(opcodeRef, XREF_ALL) && (stringXref.from >= cmd.ea) && (stringXref.from <= cmd.ea + op.offb))
            {
                auto str = strInfo->Read();

                if (!str.length())
                    continue;

                references.emplace_back(str, cmd.ea + op.offb, (int)(xref->from - (cmd.ea + op.offb)));
            }
        }
    }
}

void Plugin::SortAndPrint(std::vector<RefInfo>& references)
{
    std::sort(references.begin(), references.end(), [](const RefInfo& a, const RefInfo& b)
    {
        return std::abs(a.offset) > std::abs(b.offset);
    });

    for (auto& i : references)
    {
        if (i.offset < 0)
            msg("%a - 0x%X %s\n", i.stringRef, std::abs(i.offset), i.str.c_str());
        else
            msg("%a + 0x%X %s\n", i.stringRef, i.offset, i.str.c_str());
    }
}
