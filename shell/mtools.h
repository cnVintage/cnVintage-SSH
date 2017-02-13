#pragma once

#include <vector>
#include <string>
#include <sstream>
#include <iostream>

struct folder
{
    std::string name;
    folder *parent;
    std::vector<std::string> files;
    std::vector<folder*> folders;

    void printlocal()
    {
        using namespace std;
        cout << name << ":\t" << this << endl;
    }

    folder(std::string name)
    {
        this->name = name;
        this->parent = nullptr;
    }

    folder()
    {
        this->name = "undefined";
        this->parent = nullptr;
    }

    void addClip(folder &child)
    {
        folders.push_back(&child);
        child.parent = this;
    }

    std::string getPath()
    {
        if (this->name == "/")
            return std::string("");
        return parent->getPath() + "/" + name;
    }

    int where(std::string childName)
    {
        using namespace std;
        int pos = 0;
        for (folder* tempfolder : folders)
        {
            if (tempfolder->name == childName)
                return pos;
            pos++;
        }
        return -1;
    }

    void dispose()
    {
        for (folder *child : folders)
        {
            child->dispose();
            child = nullptr;
        }
        delete this;
    }
};

typedef struct folder folder;

int moveToPath(std::string path, folder &cwd);
void showChild(folder cwd, std::string leftpad);
