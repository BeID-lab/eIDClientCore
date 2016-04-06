#include <string>
#include <wx/string.h>
#include <list>

#ifndef ERRORMESSAGES_H
#define ERRORMESSAGES_H

#include "wx/wxprec.h"
 
#ifndef WX_PRECOMP
#   include "wx/wx.h"
#endif

using namespace std;


class ErrorMessageApp: public wxApp {
    public:
        ErrorMessageApp(string error);
        virtual bool OnInit();
        void showError(string error);

    private:
        string mError;
};


int showErrorMessage(string error);

#endif
