#pragma once

#include <memory>
#include <map>
#include <string>

#include <pro.h>
#include <strlist.hpp>

class IDAString : public string_info_t
{
public:
    IDAString();

    std::string Read() const;
    std::string ReadA() const;
    std::wstring ReadW() const;
};

// Purpose: faster than looping through the entire string list every time we want to check something.
class IDAStringList
{
public:
    IDAStringList();

    void Populate();
    void Refresh();

    auto operator[](ea_t key) {
        return m_stringList[key];
    }

private:
    std::map<ea_t, std::shared_ptr<IDAString>> m_stringList;
    unsigned int m_lastKnownQuantity;
};