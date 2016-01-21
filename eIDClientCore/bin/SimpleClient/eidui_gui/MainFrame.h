#include <string>
#include <wx/string.h>
#include <list>


#ifndef MAINFRAME_H
#define MAINFRAME_H

#include "wx/wxprec.h"
 
#ifndef WX_PRECOMP
#   include "wx/wx.h"
#endif


using namespace std;

const wxString tt_is[] = {
    "Read Fingerprint",
    "Read Iris",
    "Read eID"
};

const wxString tt_at[] = {
    "Verify Age",
    "Verify Community ID",
    "Restricted ID",
    "Privileged Terminal",
     "CAN allowed",
     "PIN Management",
     "Install Certificate",
     "Install Qualified Certificate",
     "Read Document Type",
     "Read Issuing State",
     "Read Date of Expiry",
     "Read Given Names",
     "Read Family Names",
     "Read Religious/Artistic Name",
     "Read Academic Title",
     "Read Date of Birth",
     "Read Place of Birth",
     "Read Nationality",
     "Read Sex",
     "Read OptionalDataR (DG12)",
     "Read Birth Name",
     "Read DG 14",
     "Read DG 15",
     "Read DG 16",
     "Read Normal Place of Residence",
     "Read Community ID",
     "Read Residence Permit I",
     "Read Residence Permit II",
     "Read OptionalDataRW (DG21)",
     "Write OptionalDataRW (DG21)",
     "Write Residence Permit I",
     "Write Residence Permit II",
     "Write Community ID",
     "Write Normal Place of Residence"
};

const wxString tt_st[] = {
    "Generate electronic signature",
    "Generate qualified electronic signature"
};

class MainFrame: public wxFrame {
    public:
        MainFrame(const SPDescription_t *description, UserInput_t *input, int *status, const wxString& title, const wxPoint& pos, const wxSize& size);

    private:
        void ShowServiceInfo(wxPanel *panel, wxBoxSizer *hbox);
        void ShowTerminalInfo(wxPanel *panel, wxBoxSizer *hbox);
        void SetUserInput();
        void OnExit(wxCommandEvent& event);
        void OnAbout(wxCommandEvent& event);
        void OnButtonOK(wxCommandEvent& event);
        void OnButtonCancel(wxCommandEvent& event);
        bool getPinFromUser();
        void addCheckBox(int id, bool required, bool optional, wxString name);
        wxDECLARE_EVENT_TABLE();
        wxPanel *panel;
        wxGridSizer *grid_sizer;
        wxTextCtrl *status_text;

        wxCheckListBox *clb_terminal_info;
        list<wxCheckBox*> checkBoxes;
        const SPDescription_t *m_description;
        UserInput_t *m_input;
        int *m_status;

};

class MainApp: public wxApp {
    public:
        MainApp(const SPDescription_t *description, UserInput_t *input, int *status);
        virtual bool OnInit();
        void appendText(string text);

    private:
        MainFrame *frame;
        const SPDescription_t *m_description;
        UserInput_t *m_input;
        int *m_status;
};

class CheckBox : public wxFrame
{
public:


};

const int ID_CHECKBOX = 100;
const int ID_CHECKLISTBOX = 101;


int start_gui(const SPDescription_t *description, UserInput_t *input);



#endif
