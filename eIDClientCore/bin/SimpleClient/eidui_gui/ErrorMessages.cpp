#include <eIDClientCore.h>
#include <string>
#include <wx/string.h>
#include <wx/wx.h>
#include <wx/richtext/richtextctrl.h>
#include <wx/sizer.h>
#include <wx/window.h>
#include <wx/textdlg.h> 
#include <wx/checkbox.h>
#include <wx/msgdlg.h>
#include <wx/dialog.h>
#include <string.h>

// For compilers that don't support precompilation, include "wx/wx.h"
#include <wx/wxprec.h>
#ifndef WX_PRECOMP
    #include <wx/wx.h>
#endif

#include "ErrorMessages.h"

using namespace std;

ErrorMessageApp* eApp;


bool ErrorMessageApp::OnInit()
{
    wxString errorString(mError.c_str(), wxConvUTF8);

    wxMessageDialog *dial = new wxMessageDialog(NULL, errorString, wxT("Info"), wxOK);
    dial->ShowModal();

    exit(1);
    return(false);
}

ErrorMessageApp::ErrorMessageApp(string error) 
        : wxApp()
{
    mError = error;
}

void ErrorMessageApp::showError(string error) {

}

int showErrorMessage(string error)
{

    char **argv_ = NULL;
    int argc_ = 0;   

    eApp = new ErrorMessageApp(error); 

    wxApp::SetInstance(eApp);
    wxEntry(argc_, argv_);


    return 0;
}

