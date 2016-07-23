#pragma once

#include <memory>
#include <map>
#include <string>

#include <pro.h>
#include <strlist.hpp>

class IDAString
{
public:
    IDAString();
    IDAString(ea_t address, int type, unsigned int len);

    std::string Read() const;
    std::string ReadA() const;
    std::wstring ReadW() const;

    operator int() const {
        return m_type;
    }

    ea_t GetEA() const {
        return m_address;
    }

    int GetType() const {
        return m_type;
    }

    int GetLength() const {
        return m_length;
    }

private:
    // eh, can't hurt.
    ea_t m_address;

    int m_type;
    unsigned int m_length;
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