#include <thread> 
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


// For compilers that don't support precompilation, include "wx/wx.h"
#include <wx/wxprec.h>
#ifndef WX_PRECOMP
    #include <wx/wx.h>
#endif

#include "MainFrame.h"



using namespace std;

enum
{
    ID_Hello = 1,
    TEXT_Main = 2,
    wxID_BUTTON_OK = 3,
    wxID_BUTTON_CANCEL = 4
};

enum is {
    is_read_finger = 101,
    is_read_iris = 102,
    is_RFU1 = 103,
    is_RFU2 = 105,
    is_RFU3 = 106,
    is_read_eid = 107,
    is_role = 108,
};

enum st {
    st_generate_signature = 201,
    st_generate_qualified_signature = 202,
    st_RFU1 = 203,
    st_RFU2 = 204,
    st_RFU3 = 205,
    st_RFU4 = 206,
    st_role = 207,
};

enum at {
    at_age_verification = 301,
    at_community_id_verification = 302,
    at_restricted_id = 303,
    at_privileged = 304,
    at_can_allowed = 305,
    at_pin_management = 306,
    at_install_cert = 307,
    at_install_qualified_cert = 308,
    at_read_dg1 = 309,
    at_read_dg2 = 310,
    at_read_dg3 = 311,
    at_read_dg4 = 312,
    at_read_dg5 = 313,
    at_read_dg6 = 314,
    at_read_dg7 = 315,
    at_read_dg8 = 316,
    at_read_dg9 = 317,
    at_read_dg10 = 318,
    at_read_dg11 = 319,
    at_read_dg12 = 320,
    at_read_dg13 = 321,
    at_read_dg14 = 322,
    at_read_dg15 = 323,
    at_read_dg16 = 324,
    at_read_dg17 = 325,
    at_read_dg18 = 326,
    at_read_dg19 = 327,
    at_read_dg20 = 328,
    at_read_dg21 = 329,
    at_write_dg17 = 330,
    at_write_dg18 = 331,
    at_write_dg19 = 332,
    at_write_dg20 = 333,
    at_write_dg21 = 334,
    at_RFU1 = 335,
    at_RFU2 = 336,
    at_RFU3 = 337,
    at_RFU4 = 338,
    at_role = 339,
};



wxBEGIN_EVENT_TABLE(MainFrame, wxFrame)
    EVT_MENU(wxID_EXIT,  MainFrame::OnExit)
    EVT_BUTTON ( wxID_BUTTON_OK, MainFrame::OnButtonOK)
    EVT_BUTTON ( wxID_BUTTON_CANCEL, MainFrame::OnButtonCancel)
wxEND_EVENT_TABLE()


#define MAX(a,b) (a>b ? a : b)
bool MainApp::OnInit()
{
    frame = new MainFrame(m_description, m_input, m_status, "SimpleClient", wxPoint(50, 50), wxSize(700, 700) );
    frame->Show( true );
    
    return true;
}

MainApp::MainApp(const SPDescription_t *description, UserInput_t *input, int *status) 
        : wxApp()
{
    m_description = description;
    m_input = input;
    m_status = status;
}


void MainFrame::ShowServiceInfo(wxPanel *panel, wxBoxSizer *hbox) {
    char buf[1024];
    snprintf(buf, MAX(sizeof buf, m_description->name.bufferSize), (char *) m_description->name.pDataBuffer);
    buf[(sizeof buf) - 1] = '\0';

    wxRichTextCtrl *status_text = new wxRichTextCtrl(panel, wxID_ANY, wxEmptyString, wxPoint(-1, -1), wxSize(-1, 300), wxTE_MULTILINE);

    status_text->BeginBold();
    status_text->WriteText(wxString::FromUTF8(buf));
    status_text->WriteText(_("\n"));
    status_text->EndBold();

    snprintf(buf, MAX(sizeof buf, m_description->url.bufferSize), (char *) m_description->url.pDataBuffer);
    buf[(sizeof buf) - 1] = '\0';
    status_text->WriteText(wxString::FromUTF8(buf));
    status_text->WriteText(_("\n"));

    snprintf(buf, MAX(sizeof buf, m_description->description.bufferSize), (char *) m_description->description.pDataBuffer);
    buf[(sizeof buf) - 1] = '\0';
    status_text->WriteText(wxString::FromUTF8(buf));
    status_text->WriteText(_("\n"));

    hbox->Add(status_text, 1, wxEXPAND);
}

void MainFrame::addCheckBox(int id, bool required, bool optional, wxString name) {
    wxCheckBox *item =  new wxCheckBox(panel, id, name, wxDefaultPosition, wxDefaultSize, 0, wxDefaultValidator, _T("ID_CHECKLISTBOX"));
    if(required || optional) {
        item->SetValue(true);
    }
    if(!optional) {
        item->Disable();
    }
    checkBoxes.push_back(item);
}

// sets all necessary checkboxes
void MainFrame::ShowTerminalInfo(wxPanel *panel, wxBoxSizer *hbox) {
   
    switch (m_description->chat_required.type) {
        case TT_IS:
            addCheckBox(is_read_finger, m_description->chat_required.authorization.is.read_finger, m_description->chat_optional.authorization.is.read_finger, "Fingerabdruck lesen");
            addCheckBox(is_read_iris, m_description->chat_required.authorization.is.read_iris, m_description->chat_optional.authorization.is.read_iris, "Iris lesen");
            addCheckBox(is_read_eid, m_description->chat_required.authorization.is.read_eid, m_description->chat_optional.authorization.is.read_eid, "eID lesen");
            break;

        case TT_AT:
            addCheckBox(at_age_verification, m_description->chat_required.authorization.at.age_verification, m_description->chat_optional.authorization.at.age_verification, "Altersnachweis");
            addCheckBox(at_community_id_verification, m_description->chat_required.authorization.at.community_id_verification, m_description->chat_optional.authorization.at.community_id_verification, "Bestätigung des Wohnorts");
            addCheckBox(at_restricted_id, m_description->chat_required.authorization.at.restricted_id, m_description->chat_optional.authorization.at.restricted_id, "Restricted ID");
            addCheckBox(at_privileged, m_description->chat_required.authorization.at.privileged, m_description->chat_optional.authorization.at.privileged, "Privilegiertes Terminal");
            addCheckBox(at_can_allowed, m_description->chat_required.authorization.at.can_allowed, m_description->chat_optional.authorization.at.can_allowed, "CAN erlaubt");
            addCheckBox(at_pin_management, m_description->chat_required.authorization.at.pin_management, m_description->chat_optional.authorization.at.pin_management, "PIN Management");
            addCheckBox(at_install_cert, m_description->chat_required.authorization.at.install_cert, m_description->chat_optional.authorization.at.install_cert, "Zertifikat installieren");
            addCheckBox(at_install_qualified_cert, m_description->chat_required.authorization.at.install_qualified_cert, m_description->chat_optional.authorization.at.install_qualified_cert, "Qualifiziertes Zertifikat installieren");
            addCheckBox(at_read_dg1, m_description->chat_required.authorization.at.read_dg1, m_description->chat_optional.authorization.at.read_dg1, "Dokumententyp lesen");
            addCheckBox(at_read_dg2, m_description->chat_required.authorization.at.read_dg2, m_description->chat_optional.authorization.at.read_dg2, "Ausstellenden Staat lesen");
            addCheckBox(at_read_dg3, m_description->chat_required.authorization.at.read_dg3, m_description->chat_optional.authorization.at.read_dg3, "Ablaufdatum lesen");
            addCheckBox(at_read_dg4, m_description->chat_required.authorization.at.read_dg4, m_description->chat_optional.authorization.at.read_dg4, "Vornamen lesen");
            addCheckBox(at_read_dg5, m_description->chat_required.authorization.at.read_dg5, m_description->chat_optional.authorization.at.read_dg5, "Familiennamen lesen");
            addCheckBox(at_read_dg6, m_description->chat_required.authorization.at.read_dg6, m_description->chat_optional.authorization.at.read_dg6, "Künstlernamen lesen");
            addCheckBox(at_read_dg7, m_description->chat_required.authorization.at.read_dg7, m_description->chat_optional.authorization.at.read_dg7, "Akademischen Titel lesen");
            addCheckBox(at_read_dg8, m_description->chat_required.authorization.at.read_dg8, m_description->chat_optional.authorization.at.read_dg8, "Geburtsdatum lesen");
            addCheckBox(at_read_dg9, m_description->chat_required.authorization.at.read_dg9, m_description->chat_optional.authorization.at.read_dg9, "Geburtsort lesen");
            addCheckBox(at_read_dg10, m_description->chat_required.authorization.at.read_dg10, m_description->chat_optional.authorization.at.read_dg10, "Staatszugehörigkeit lesen");
            addCheckBox(at_read_dg11, m_description->chat_required.authorization.at.read_dg11, m_description->chat_optional.authorization.at.read_dg11, "Geschlecht lesen");
            addCheckBox(at_read_dg12, m_description->chat_required.authorization.at.read_dg12, m_description->chat_optional.authorization.at.read_dg12, "DG12 lesen");
            addCheckBox(at_read_dg13, m_description->chat_required.authorization.at.read_dg13, m_description->chat_optional.authorization.at.read_dg13, "DG13 lesen");
            addCheckBox(at_read_dg14, m_description->chat_required.authorization.at.read_dg14, m_description->chat_optional.authorization.at.read_dg14, "DG14 lesen");
            addCheckBox(at_read_dg15, m_description->chat_required.authorization.at.read_dg15, m_description->chat_optional.authorization.at.read_dg15, "DG15 lesen");
            addCheckBox(at_read_dg16, m_description->chat_required.authorization.at.read_dg16, m_description->chat_optional.authorization.at.read_dg16, "DG16 lesen");
            addCheckBox(at_read_dg17, m_description->chat_required.authorization.at.read_dg17, m_description->chat_optional.authorization.at.read_dg17, "Adresse lesen");
            addCheckBox(at_read_dg18, m_description->chat_required.authorization.at.read_dg18, m_description->chat_optional.authorization.at.read_dg18, "Wohnort-ID lesen");
            addCheckBox(at_read_dg19, m_description->chat_required.authorization.at.read_dg19, m_description->chat_optional.authorization.at.read_dg19, "Aufenthaltserlaubnis I lesen");
            addCheckBox(at_read_dg20, m_description->chat_required.authorization.at.read_dg20, m_description->chat_optional.authorization.at.read_dg20, "Aufenthaltserlaubnis II lesen");
            addCheckBox(at_read_dg21, m_description->chat_required.authorization.at.read_dg21, m_description->chat_optional.authorization.at.read_dg21, "DG21 lesen");
            addCheckBox(at_write_dg21, m_description->chat_required.authorization.at.write_dg21, m_description->chat_optional.authorization.at.write_dg21, "DG21 ändern");
            addCheckBox(at_write_dg20, m_description->chat_required.authorization.at.write_dg20, m_description->chat_optional.authorization.at.write_dg20, "Aufenthaltserlaubnis I ändern");
            addCheckBox(at_write_dg19, m_description->chat_required.authorization.at.write_dg19, m_description->chat_optional.authorization.at.write_dg19, "Aufenthaltserlaubnis II ändern");
            addCheckBox(at_write_dg18, m_description->chat_required.authorization.at.write_dg18, m_description->chat_optional.authorization.at.write_dg18, "Wohnort-ID ändern");
            addCheckBox(at_write_dg17, m_description->chat_required.authorization.at.write_dg17, m_description->chat_optional.authorization.at.write_dg17, "Adresse ändern");
            break;

        case TT_ST:
            addCheckBox(st_generate_signature, m_description->chat_required.authorization.st.generate_signature, m_description->chat_optional.authorization.st.generate_signature, "Elektronische Signatur erzeugen");
            addCheckBox(st_generate_qualified_signature, m_description->chat_required.authorization.st.generate_qualified_signature, m_description->chat_optional.authorization.st.generate_qualified_signature, "Qualifizierte elektronische Signatur erzeugen");
            break;

        default:
            break;
    }



    wxBoxSizer *vbox1 = new wxBoxSizer(wxVERTICAL);
    wxBoxSizer *vbox2 = new wxBoxSizer(wxVERTICAL);
    wxBoxSizer *vbox3 = new wxBoxSizer(wxVERTICAL);

    // display checkboxes in 3 raws
    int counter = 0;
    for (list<wxCheckBox*>::iterator i=checkBoxes.begin(); i != checkBoxes.end(); i++) {
        if(counter < 12) {
            vbox1->Add(*i);
        }
        else if(counter < 24){
            vbox2->Add(*i);
        }
        else {
            vbox3->Add(*i);
        }
        counter++;
    }

    hbox->Add(vbox1);
    hbox->Add(vbox2);
    hbox->Add(vbox3);

}

void MainFrame::SetUserInput() {
    // set user input
}


MainFrame::MainFrame(const SPDescription_t *description, UserInput_t *input, int *status, const wxString& title, const wxPoint& pos, const wxSize& size)
        : wxFrame(NULL, wxID_ANY, title, pos, size)
{
    m_description = description;
    m_input = input;
    m_status = status;
    Centre();
    wxMenu *menuFile = new wxMenu;

    // Menu
    // menuFile->Append(wxID_EXIT);
    // wxMenu *menuHelp = new wxMenu;
    // menuHelp->Append(wxID_ABOUT);
    // wxMenuBar *menuBar = new wxMenuBar;
    // menuBar->Append( menuFile, "&File" );
    // menuBar->Append( menuHelp, "&Help" );
    // SetMenuBar( menuBar );
    // CreateStatusBar();

    // layout
    panel = new wxPanel(this, -1);
    wxBoxSizer *vbox = new wxBoxSizer(wxVERTICAL);

    // first label
    wxBoxSizer *hbox2 = new wxBoxSizer(wxHORIZONTAL);
    wxStaticText *label_services = new wxStaticText(panel, wxID_ANY, wxT("Dienstanbieter: "));
    hbox2->Add(label_services, 0);
    vbox->Add(hbox2, 0, wxEXPAND | wxLEFT | wxRIGHT | wxTOP, 10);

    // service info
    wxBoxSizer *hbox3 = new wxBoxSizer(wxHORIZONTAL);
    
    ShowServiceInfo(panel, hbox3);
    
    // hbox3->Add(status_text, 1, wxEXPAND);
    vbox->Add(hbox3, 1, wxLEFT | wxRIGHT | wxEXPAND, 10);
    panel->SetSizer(vbox);

    // second label
    wxBoxSizer *hbox4 = new wxBoxSizer(wxHORIZONTAL);
    wxStaticText *label_terminalinfo = new wxStaticText(panel, wxID_ANY, wxT("Daten: "));
    hbox4->Add(label_terminalinfo, 0);
    vbox->Add(hbox4, 0, wxEXPAND | wxLEFT | wxRIGHT | wxTOP, 10);

    // terminal info (checkboxes)
    wxBoxSizer *hbox_checkboxes = new wxBoxSizer(wxHORIZONTAL);

    ShowTerminalInfo(panel, hbox_checkboxes);

    vbox->Add(hbox_checkboxes, 0, wxEXPAND | wxLEFT | wxRIGHT | wxTOP, 10);


    // pin
    if(m_input->pin_required && m_input->pin.bufferSize == 0) {
        wxBoxSizer *hbox5 = new wxBoxSizer(wxHORIZONTAL);
        wxStaticText *label_pin = new wxStaticText(panel, wxID_ANY, wxT("Pin: "));
        hbox5->Add(label_pin, 0);
        m_passwordEntry = new wxTextCtrl(panel, wxID_ANY, wxString(""), wxDefaultPosition, wxDefaultSize, wxTE_PASSWORD);
        hbox5->Add(m_passwordEntry, 1);
        vbox->Add(hbox5, 0, wxEXPAND | wxLEFT | wxRIGHT | wxTOP, 10);
    }


    // buttons
    wxBoxSizer *hbox6 = new wxBoxSizer(wxHORIZONTAL);
    wxButton *button_cancel = new wxButton(panel, wxID_BUTTON_CANCEL, wxT("Abbrechen"));
    hbox6->Add(button_cancel, 0);
    wxButton *button_ok = new wxButton(panel, wxID_BUTTON_OK, wxT("OK"));
    hbox6->Add(button_ok, 0, wxLEFT | wxBOTTOM , 5);
    vbox->Add(hbox6, 0, wxALIGN_RIGHT | wxRIGHT, 10);
}

bool MainFrame::getPinFromUser() {
    if(!m_input->pin_required) {
        return true;
    }

    if(m_input->pin.bufferSize == 0){
        wxString pin = m_passwordEntry->GetValue();

        // wxString pin = wxGetPasswordFromUser(_("Geben Sie bitte Ihre PIN ein!"), _("PIN-Eingabe"), wxEmptyString, NULL, 0, 0, true);


        if (pin == wxEmptyString) {
            wxMessageDialog *dialog = new wxMessageDialog(NULL, wxT("Bitte geben Sie Ihre Pin ein."), wxT("Info"), wxOK | wxICON_EXCLAMATION);
            dialog->ShowModal();
            return false;
        }

        strncpy ((char *)m_input->pin.pDataBuffer, (const char*)pin.mb_str(wxConvUTF8), MAX_PIN_SIZE);
        m_input->pin.bufferSize = strlen((char*) m_input->pin.pDataBuffer);

    }
        
    return true;
}

void MainFrame::OnExit(wxCommandEvent& event)
{
    *m_status = -1;
    Close( true );
}

void MainFrame::OnButtonOK(wxCommandEvent& event)
{
    if(getPinFromUser()) {
        *m_status = 0;
        Close( true );
    }
    
}

void MainFrame::OnButtonCancel(wxCommandEvent& event)
{
    *m_status = -1;
    Close( true );
}


int start_gui(const SPDescription_t *description, UserInput_t *input)
{
    int status = 0;

    MainApp* pApp;

    char **argv_ = NULL;
    int argc_ = 0;   

    pApp = new MainApp(description, input, &status); 

    wxApp::SetInstance(pApp);
    wxEntry(argc_, argv_);

    
    if(status == -1) {
        exit(0);
    }
    return 0;

}

