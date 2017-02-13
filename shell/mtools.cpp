#include <vector>
#include <iostream>
#include "mtools.h"

std::string& replaceAll(std::string& str, const std::string& old_value, const std::string& new_value)
{
    using namespace std;

    for (string::size_type pos(0); pos != string::npos; pos += new_value.length()) {
        if ((pos = str.find(old_value, pos)) != string::npos)
            str.replace(pos, old_value.length(), new_value);
        else break;
    }
    return str;
}

int moveToPath(std::string path, folder &cwd)
{
    using namespace std;

    folder *tempcwd = &cwd;
    replaceAll(path, "/", " ");
    stringstream ss(path);
    
    string temps;
    while (ss >> temps)
    {
        if (temps == "..")
        {
            tempcwd = tempcwd->parent;
            continue;
        }

        if (temps == ".")
            continue;
        int folderpos = tempcwd->where(temps);
        if (folderpos == -1)
            return -1;
        tempcwd = tempcwd->folders[folderpos];
    }

    cwd = *tempcwd;

    return 0;
}

void showChild(folder cwd, std::string leftpad) 
{
    using namespace std;

    cout << leftpad << "+- " << cwd.name << endl;

    leftpad += "|  ";
    for (folder *optfolder : cwd.folders)
    {
        showChild(*optfolder, leftpad);
    }
    for (string opts : cwd.files)
    {
        cout << leftpad << opts << endl;
    }
}
