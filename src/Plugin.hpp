#pragma once

#include <string>
#include <vector>

#include "IDAStringList.hpp"

struct RefInfo
{
    RefInfo(const std::string& a, ea_t b, int c)
        : str(a),
        stringRef(b),
        offset(c)
    {

    }

    std::string str;
    ea_t stringRef;
    int offset;
};

class Plugin
{
public:
    Plugin();

    // IDA required functions
    void OnRun(int arg);

    int OnInit();
    void OnTerminate();

private:
    void FillReferences(std::vector<RefInfo>& references);
    void OnXRef(struct xrefblk_t* xref, std::vector<RefInfo>& references);
    void SortAndPrint(std::vector<RefInfo>& references);

public:
    static constexpr int   flags   = 0;
    static constexpr char* comment = "Finds string references near a reference.";
    static constexpr char* name    = "String Reference Locator";
    static constexpr char* help    = "Finds string references near a reference.";
    static constexpr char* hotkey  = "Ctrl+Alt+Q";

private:
    IDAStringList m_stringList;

};

extern Plugin plugin;