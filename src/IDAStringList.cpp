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
        std::shared_ptr<IDAString> si = std::make_shared<IDAString>();
        get_strlist_item(i, si.get());

        m_stringList[si->ea] = si;
    }
}

void IDAStringList::Refresh()
{
    refresh_strlist(inf.minEA, inf.maxEA);
}

IDAString::IDAString()
{
    type = -1;
    ea = 0;
    length = 0;
}

std::string IDAString::Read() const
{
    if (type == 0)
        return ReadA();
    else
    {
        auto wrap = ReadW();
        return std::string(wrap.begin(), wrap.end());
    }
}

std::string IDAString::ReadA() const
{
    std::unique_ptr<unsigned char[]> buf(new unsigned char[length]);
    get_many_bytes(ea, buf.get(), length);

    for (int i = 0; i < length; ++i)
    {
        if (buf.get()[i] == '\0')
            break;

        if (buf.get()[i] > 127)
        {
            auto wrap = ReadW();
            return std::string(wrap.begin(), wrap.end());
        }
    }

    return std::string((char*)buf.get(), length);
}

std::wstring IDAString::ReadW() const
{
    std::unique_ptr<wchar_t[]> buf(new wchar_t[length]);
    get_many_bytes(ea, buf.get(), length);

    return std::wstring(buf.get(), length);
}
