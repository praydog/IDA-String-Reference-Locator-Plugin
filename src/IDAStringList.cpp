#include "IDAStringList.hpp"

#include <ida.hpp>
#include <bytes.hpp>

IDAStringList::IDAStringList()
    : m_lastKnownQuantity(0)
{

}

void IDAStringList::Populate()
{
    auto currentQuantity = get_strlist_qty();

    if (!m_stringList.size() || m_lastKnownQuantity != currentQuantity)
    {
        Refresh();
        currentQuantity = get_strlist_qty();
    }

    m_lastKnownQuantity = currentQuantity;
    m_stringList.clear();

    for (size_t i = 0; i < currentQuantity; i++)
    {
        string_info_t si;
        get_strlist_item(i, &si);

        m_stringList[si.ea] = std::make_shared<IDAString>(si.ea, si.type, si.length);
    }
}

void IDAStringList::Refresh()
{
    refresh_strlist(inf.minEA, inf.maxEA);
}

IDAString::IDAString() 
    : m_type(-1),
    m_length(0),
    m_address(0)
{

}

IDAString::IDAString(ea_t address, int type, unsigned int len) 
    : m_type(type),
    m_length(len),
    m_address(address)
{

}

std::string IDAString::Read() const
{
    if (m_type == 0)
        return ReadA();
    else
    {
        auto wrap = ReadW();
        return std::string(wrap.begin(), wrap.end());
    }
}

std::string IDAString::ReadA() const
{
    std::unique_ptr<unsigned char[]> buf(new unsigned char[m_length]);
    get_many_bytes(m_address, buf.get(), m_length);

    for (unsigned int i = 0; i < m_length; ++i)
    {
        if (buf.get()[i] == '\0')
            break;

        if (buf.get()[i] > 127)
        {
            auto wrap = ReadW();
            return std::string(wrap.begin(), wrap.end());
        }
    }

    return std::string((char*)buf.get());
}

std::wstring IDAString::ReadW() const
{
    std::unique_ptr<wchar_t[]> buf(new wchar_t[m_length]);
    get_many_bytes(m_address, buf.get(), 256);

    return std::wstring(buf.get());
}
