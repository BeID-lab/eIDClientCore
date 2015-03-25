#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>

#include <QAction>
#include <QComboBox>
#include <QKeySequence>
#include <QLabel>
#include <QMenu>
#include <QMenuBar>
#include <QPlainTextEdit>
#include <QPixmap>
#include <QProcess>
#include <QPushButton>
#include <QRadioButton>
#include <QStackedLayout>
#include <QStackedWidget>
#include <QVBoxLayout>
#include <string>

#include "eIDClientCore.h"


class MainWindow : public QMainWindow {
     Q_OBJECT

public:
	static MainWindow* getInstance();
	static NPACLIENT_ERROR nPAeIdUserInteractionCallback(const SPDescription_t *, UserInput_t *);
	static void nPAeIdProtocolStateCallback(const NPACLIENT_STATE, const NPACLIENT_ERROR);	
	static void eIDStatusTextFieldAppend(const QString msg, const NPACLIENT_ERROR error);
	static void eIDStatusTextFieldAppend(const QString msg);
	QString certificateDescription;

private slots:
	void handleAbbortAccessRightsButton();
	void handleConfirmAccessRightsButton();
	void handleCertificateDetailsButton();
	void handleTestcaseButton();
	void handleTestSelectAllAccessRightsButton();
	void handleTestSelectSomeAccessRightsButton();
	void showHelpWidget();
	void showPinManagementWidget();
	void showTestcaseChoiceWidget();
	void showAccessRightsChoiceWidget();
	void showEIDStatusWidget();
	void showEIDOutputWidget();

private:
	MainWindow();
	//Singleton design pattern:
	//http://stackoverflow.com/questions/1008019/c-singleton-design-pattern
        // Dont forget to declare these two. You want to make sure they
        // are unacceptable otherwise you may accidentally get copies of
        // your singleton appearing.
        MainWindow(MainWindow const&);              	// Don't Implement
        void operator=(MainWindow const&); 		// Don't implement
	static MainWindow* _instance;

	void createActions();
	void createMenus();

	void createMainWidget();
	void createLogoWidget();
	void createHelpWidget();
	void createPinManagementWidget();
	void createTestcaseWidget();
	void createAccessRightsChoiceWidget();
	void createEIDStatusWidget();
	void createEIDOutputWidget();
	void createSimpleClientThread();
	void setAccessRightsRadioButtonMandatory(QRadioButton *rb);
	void setAccessRightsRadioButtonNotRequested(QRadioButton *rb);
	void setAccessRightsRadioButtonOptional(QRadioButton *rb);
	void simulateInitAccessRightsRadioButtonsExample();
	void simulateInitAccessRightsRadioButtonsAllOptional();

	QMenu *fileMenu;
	QAction *helpAct;
	QAction *pinAct;
	QAction *testcaseAct;
	QAction *accessRightsChoiceAct;
	QAction *eIDOutputAct;
	QAction *eIDStatusAct;
	
	QHBoxLayout *mainLayout;
	QPixmap *logoImage;
	QLabel *logoLabel;
	QHBoxLayout *logoLayout;	
	QWidget *logoWidget;	
	QStackedWidget *applicationStackedWidget;	
	QVBoxLayout *helpLayout;
	QVBoxLayout *pinManagementLayout;
	QVBoxLayout *testcaseChoiceLayout;
	QVBoxLayout *accessRightsChoiceLayout;
	QVBoxLayout *testAccessRightsChoiceLayout;
	QVBoxLayout *eIDStatusLayout;
	QVBoxLayout *eIDOutputLayout;
	QWidget *helpWidget;
	QWidget *pinManagementWidget;
	QWidget *testcaseChoiceWidget;
	QWidget *accessRightsChoiceWidget;
	QWidget *eIDStatusWidget;
	QWidget *eIDOutputWidget;

	QWidget *mainWidget;

	QLabel *helpTextLabel;
	QLabel *pinManagementLabel;


	//Elements of the AccessRightsChoiceWidget for checking and adapting the CHAT
	QHBoxLayout *serviceProviderLayout;
	QLabel *serviceProviderInfoLabel;
	QLabel *serviceProviderLabel;
	QHBoxLayout *purposeOfUseLayout;
	QLabel *purposeOfUseInfoLabel;
	QLabel *purposeOfUseLabel;
	QPushButton *showCertificateDetailsButton;
	QLabel *accessRightsChoiceInfoLabel;
	QVBoxLayout *accessRightsChoiceSelectionLayout;
	QRadioButton *documentTypeRadioButton;
	QRadioButton *issuingCountryRadioButton;
	QRadioButton *validUntilRadioButton;
	QRadioButton *givenNameRadioButton;
	QRadioButton *familyNameRadioButton;
	QRadioButton *religiousOrArtisticalNameRadioButton;
	QRadioButton *doctoralDegreeRadioButton;
	QRadioButton *birthDateRadioButton;
	QRadioButton *birthPlaceRadioButton;
	QRadioButton *nationalityRadioButton;
	QRadioButton *birthNameRadioButton;
	QRadioButton *adressRadioButton;
	QRadioButton *auxConditionsRadioButton;
	QRadioButton *pseudonymRadioButton;
	QRadioButton *verificationAdressRadioButton;
	QRadioButton *verificationAgeRadioButton;
	QHBoxLayout *accessRightsConfirmationLayout;
	QHBoxLayout *testAccessRightsConfirmationLayout;
	QPushButton *confirmAccessRightsButton;
	QPushButton *abbortAccessRightsButton;
	QPushButton *testSelectAllAccessRightsButton;
	QPushButton *testSelectSomeAccessRightsButton;
	
	//Elements of the TestcaseChoiceWidget
	QLabel *testcaseLabel;
	QPushButton *startTestcaseButton;
	QString TestcaseAutentApp;
	QString TestcaseNoSaml;
	QString TestcaseSaml1;
	QString TestcaseSaml2;
	QString TestcaseSelbstauskunftWuerzburg;
	QComboBox *testcaseCombo;

	//Elements of EIDStatusWidget	
	QPlainTextEdit *eIDStatusTextField;
	QString eIDStatus;

	//Elements of EiDOutputWidget
	QPlainTextEdit *eIDOutputTextField;
	QString eIDOutput;

};
#endif
