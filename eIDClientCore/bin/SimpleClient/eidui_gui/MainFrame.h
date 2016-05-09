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
    "Fingerabdruck lesen",
    "Iris lesen",
    "eID lesen"
};

const wxString tt_at[] = {
    "Altersnachweis",
    "Bestätigung des Wohnorts",
    "Restricted ID",
    "Privilegiertes Terminal",
     "CAN erlaubt",
     "PIN Management",
     "Zertifikat installieren",
     "Qualifiziertes Zertifikat installieren",
     "Dokumententyp lesen",
     "Ausstellenden Staat lesen",
     "Ablaufdatum lesen",
     "Vornamen lesen",
     "Familiennamen lesen",
     "Künstlernamen lesen",
     "Akademischen Titel lesen",
     "Geburtsdatum lesen",
     "Geburtsort lesen",
     "Staatszugehörigkeit lesen",
     "Geschlecht lesen",
     "DG12 lesen",
     "DG13 lesen",
     "DG14 lesen",
     "DG15 lesen",
     "DG16 lesen",
     "Adresse lesen",
     "Wohnort-ID lesen",
     "Aufenthaltserlaubnis I lesen",
     "Aufenthaltserlaubnis II lesen",
     "DG21 lesen",
     "DG21 ändern",
     "Aufenthaltserlaubnis I ändern",
     "Aufenthaltserlaubnis II ändern",
     "Wohnort-ID ändern",
     "Adresse ändern"
};

const wxString tt_st[] = {
    "Elektronische Signatur erzeugen",
    "Qualifizierte elektronische Signatur erzeugen"
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
        wxTextCtrl* m_passwordEntry;

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
