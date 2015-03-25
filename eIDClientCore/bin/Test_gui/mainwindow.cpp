#include <QtGui>
#include <QStackedWidget>
#include <QDesktopServices>
#include <QMessageBox>
				
#include "mainwindow.h"

#include "eIDClientCore.h"
#include "libSimpleClient.h"

#include <thread>
#include <stdio.h>
#include <string>

static NPACLIENT_ERROR gError = NPACLIENT_ERROR_SUCCESS;
//static CeIdObject gAuthParams;
static std::string gUserInteractionHtml;
static std::string gPin;

MainWindow *MainWindow::_instance=NULL;

//Singleton
MainWindow::MainWindow() {

	createMainWidget();
	createActions();
	createMenus();
	createLogoWidget();
	mainLayout->addWidget(logoWidget);
	applicationStackedWidget = new QStackedWidget;
	mainLayout->addWidget(applicationStackedWidget);

	//todo rename createTestcaseChoiceWidget to better match naming convention
	createTestcaseWidget();
	applicationStackedWidget->addWidget(testcaseChoiceWidget);
	
	createPinManagementWidget();
	applicationStackedWidget->addWidget(pinManagementWidget);

	createHelpWidget();
	applicationStackedWidget->addWidget(helpWidget);

	createAccessRightsChoiceWidget();
	applicationStackedWidget->addWidget(accessRightsChoiceWidget);
	certificateDescription=QString();

	createEIDStatusWidget();
	applicationStackedWidget->addWidget(eIDStatusWidget);

	createEIDOutputWidget();
	applicationStackedWidget->addWidget(eIDOutputWidget);

	//change Background color, but also the color of buttons:
	//setStyleSheet("background-color: white;");
	QPalette Pal(palette());
	// set black background
	Pal.setColor(QPalette::Background, Qt::white);
	setAutoFillBackground(true);
	setPalette(Pal);

	setWindowTitle(tr("eIDClientCore GUI"));
	setMinimumSize(160, 160);//todo make bigger
	resize(1200,800);//todo make bigger

	createSimpleClientThread();
}


void MainWindow::handleAbbortAccessRightsButton() {
	printf("Abbort Acces Rights (todo): %i, in %s \n", __LINE__, __FILE__);
}

void MainWindow::handleTestSelectSomeAccessRightsButton() {
	printf("Choose some  Access Rights: %i, in %s \n", __LINE__, __FILE__);
	//Testing purpose:
	simulateInitAccessRightsRadioButtonsExample();
}

MainWindow* MainWindow::getInstance(){
	if(_instance == NULL){
		_instance = new MainWindow();
	}
	return _instance;
}

void MainWindow::handleConfirmAccessRightsButton() {
	printf("Confirm Acces Rights (todo): %i, in %s \n", __LINE__, __FILE__);
}

void MainWindow::handleTestSelectAllAccessRightsButton() {
	printf("Choose All Access Rights: %i, in %s \n", __LINE__, __FILE__);
	//Testing purpose:
	simulateInitAccessRightsRadioButtonsAllOptional();
}

void MainWindow::handleCertificateDetailsButton() {
	printf("show Certificate Details (todo): %i, in %s \n", __LINE__, __FILE__);
	QMessageBox msgBox;
	msgBox.setText("Certificate Description");
	msgBox.setInformativeText(certificateDescription);
	msgBox.exec();
}

void MainWindow::handleTestcaseButton()
{
	if(testcaseCombo->itemText(testcaseCombo->currentIndex()) == TestcaseAutentApp) {
		printf("testcase AutentApp called %i, in %s \n", __LINE__, __FILE__);
		printf("open trigger URL in webbrowser%i, in %s \n", __LINE__, __FILE__);
		QDesktopServices::openUrl(QUrl("http://127.0.0.1:24727/eID-Client?tcTokenURL=https://www.autentapp.de/AusweisAuskunft/WebServiceRequesterServlet?mode=autentappde", QUrl::TolerantMode));
	}
	else if(testcaseCombo->itemText(testcaseCombo->currentIndex()) == TestcaseNoSaml) {
		printf("testcase TestcaseNoSaml called (todo) %i, in %s \n", __LINE__, __FILE__);
	}
	else if(testcaseCombo->itemText(testcaseCombo->currentIndex()) == TestcaseSaml1) {
		printf("testcase TestcaseSaml1 called (todo) %i, in %s \n", __LINE__, __FILE__);
	}
	else if(testcaseCombo->itemText(testcaseCombo->currentIndex()) == TestcaseSaml2) {
		printf("testcase TestcaseSaml2 called (todo) %i, in %s \n", __LINE__, __FILE__);
	}
	else if(testcaseCombo->itemText(testcaseCombo->currentIndex()) == TestcaseSelbstauskunftWuerzburg) {
		printf("testcase Testcase Selbstauskunft Würzburg called (todo) %i, in %s \n", __LINE__, __FILE__);
	}
	else {
		printf("ERROR no valid Item in testcaseCombo %i, in %s \n", __LINE__, __FILE__);
		qFatal("ERROR no valid Item in testcaseCombo %i, in %s \n", __LINE__, __FILE__);
	}
	
	
	//dummy call eIDClientCore nPAeIdPerformAuthenticationProtocol:
	//printf("Test before nPAeIdPerformAuthenticationProtocol  %i, in %s \n", __LINE__, __FILE__);
	//int returnValue = nPAeIdPerformAuthenticationProtocol(READER_PCSC,0,0,0,0,0,0,0);
	//int returnValue = nPAeIdPerformAuthenticationProtocol(READER_PCSC,0,0,0,0,0,nPAeIdUserInteractionCallback,nPAeIdProtocolStateCallback);
	//int returnValue = nPAeIdPerformAuthenticationProtocol(0,0,0,0,0,0,nPAeIdUserInteractionCallback,nPAeIdProtocolStateCallback);
	//printf("Test after nPAeIdPerformAuthenticationProtocol, return Value: %icalled in:  %i, in %s \n", returnValue, __LINE__, __FILE__);
	

}

void MainWindow::createAccessRightsChoiceWidget() {

	//submenus:
	/*menuLayout = new QVBoxLayout;
	menuWidget = new QWidget;

	QLabel *menuTextLabel = new QLabel(QString::fromUtf8("Hier könnte das Menue angezeigt werden."));
	menuLayout->addWidget(menuTextLabel);

	menuWidget->setLayout(menuLayout);*/


	accessRightsChoiceLayout = new QVBoxLayout;
	accessRightsChoiceWidget = new QWidget;

	//Certificate Service Provider:
	serviceProviderLayout = new QHBoxLayout;
	serviceProviderInfoLabel = new QLabel(QString::fromUtf8("Dienstanbieter: "));
	serviceProviderLayout->addWidget(serviceProviderInfoLabel);
	serviceProviderLabel = new QLabel(QString::fromUtf8("Beispieldienstanbieter"));	
	serviceProviderLayout->addWidget(serviceProviderLabel);
	accessRightsChoiceLayout->addLayout(serviceProviderLayout);
	
	//Certificate Purpose of Use:
	purposeOfUseLayout = new QHBoxLayout;
	purposeOfUseInfoLabel = new QLabel(QString::fromUtf8("Zweck des Auslesevorganges:"));
	purposeOfUseLayout->addWidget(purposeOfUseInfoLabel);
	purposeOfUseLabel = new QLabel(QString::fromUtf8("Beispielzweck"));
	purposeOfUseLayout->addWidget(purposeOfUseLabel);
	accessRightsChoiceLayout->addLayout(purposeOfUseLayout);

	//Button to show whole certificate:
	QString CertificateDetailsText("Berechtigungszertifikat anzeigen");
	showCertificateDetailsButton = new QPushButton(CertificateDetailsText);
	//There are different functions in fontMetrics for calculating the width (size(),width(),boundingRect()), each with slightly different Results
	//for this case I take width() and add some 'safety Pixels'
	int certificateDetailsButtonWidth = showCertificateDetailsButton->fontMetrics().width(CertificateDetailsText)+40;
	//set size and location of the button
	showCertificateDetailsButton->setGeometry(QRect(QPoint(100, 100),
	                             QSize(300, 50)));
	showCertificateDetailsButton->setMaximumWidth(certificateDetailsButtonWidth);
	//Connect Button signal to appropriate slot
	connect(showCertificateDetailsButton, SIGNAL(released()), this, SLOT(handleCertificateDetailsButton()));
	accessRightsChoiceLayout->addWidget(showCertificateDetailsButton);
	
	accessRightsChoiceInfoLabel = new QLabel(QString::fromUtf8("Folgende Daten bittet Sie der Dienstanbieter zu übermitteln. Für Grau hinterlegte Daten ist die Übermittlung Pflicht und kann nicht abgewählt werden."));
	accessRightsChoiceInfoLabel->setWordWrap(true);
	accessRightsChoiceLayout->addWidget(accessRightsChoiceInfoLabel);
	
	
	accessRightsChoiceSelectionLayout = new QVBoxLayout;
	//todo use QButtonGroup? http://qt-project.org/doc/qt-5/qbuttongroup.html
	documentTypeRadioButton = new QRadioButton("Dokumententyp");
	documentTypeRadioButton->setAutoExclusive(false);
	accessRightsChoiceSelectionLayout->addWidget(documentTypeRadioButton);
	issuingCountryRadioButton = new QRadioButton("Austellender Staat");
	issuingCountryRadioButton->setAutoExclusive(false);
	accessRightsChoiceSelectionLayout->addWidget(issuingCountryRadioButton);
	validUntilRadioButton = new QRadioButton("Gültig bis");
	validUntilRadioButton->setAutoExclusive(false);
	accessRightsChoiceSelectionLayout->addWidget(validUntilRadioButton);
	givenNameRadioButton = new QRadioButton("Vorname(n)");
	givenNameRadioButton->setAutoExclusive(false);
	accessRightsChoiceSelectionLayout->addWidget(givenNameRadioButton);
	familyNameRadioButton = new QRadioButton("Nachname");
	familyNameRadioButton->setAutoExclusive(false);
	accessRightsChoiceSelectionLayout->addWidget(familyNameRadioButton);
	religiousOrArtisticalNameRadioButton = new QRadioButton("Ordens-/Künstlername");
	religiousOrArtisticalNameRadioButton->setAutoExclusive(false);
	accessRightsChoiceSelectionLayout->addWidget(religiousOrArtisticalNameRadioButton);
	doctoralDegreeRadioButton = new QRadioButton("Akademischer Grad");
	doctoralDegreeRadioButton->setAutoExclusive(false);
	accessRightsChoiceSelectionLayout->addWidget(doctoralDegreeRadioButton);
	birthDateRadioButton = new QRadioButton("Geburtstdatum");
	birthDateRadioButton->setAutoExclusive(false);
	accessRightsChoiceSelectionLayout->addWidget(birthDateRadioButton);
	birthPlaceRadioButton = new QRadioButton("Geburtsort");
	birthPlaceRadioButton->setAutoExclusive(false);
	accessRightsChoiceSelectionLayout->addWidget(birthPlaceRadioButton);
	nationalityRadioButton = new QRadioButton("Staatsangehörigkeit");
	nationalityRadioButton->setAutoExclusive(false);
	accessRightsChoiceSelectionLayout->addWidget(nationalityRadioButton);
	//Datengruppe 13 todo
	birthNameRadioButton = new QRadioButton("Geburtsname");
	birthNameRadioButton->setAutoExclusive(false);
	accessRightsChoiceSelectionLayout->addWidget(birthNameRadioButton);
	//normal place of Residence:
	adressRadioButton = new QRadioButton("Anschrift");
	adressRadioButton->setAutoExclusive(false);
	accessRightsChoiceSelectionLayout->addWidget(adressRadioButton);
	//Aufenthalt I und II todo
	auxConditionsRadioButton = new QRadioButton("Nebenbest.");
	auxConditionsRadioButton->setAutoExclusive(false);
	accessRightsChoiceSelectionLayout->addWidget(auxConditionsRadioButton);
	pseudonymRadioButton = new QRadioButton("Pseudonym");
	pseudonymRadioButton->setAutoExclusive(false);
	accessRightsChoiceSelectionLayout->addWidget(pseudonymRadioButton);
	verificationAdressRadioButton = new QRadioButton("Wohnortbestät.");
	verificationAdressRadioButton->setAutoExclusive(false);
	accessRightsChoiceSelectionLayout->addWidget(verificationAdressRadioButton);
	verificationAgeRadioButton = new QRadioButton("Altersbestät.");
	verificationAgeRadioButton->setAutoExclusive(false);
	accessRightsChoiceSelectionLayout->addWidget(verificationAgeRadioButton);

	

	accessRightsChoiceLayout->addLayout(accessRightsChoiceSelectionLayout);

	
	accessRightsConfirmationLayout = new QHBoxLayout;
	confirmAccessRightsButton = new QPushButton("Übertragung starten");
	connect(confirmAccessRightsButton, SIGNAL(released()), this, SLOT(handleConfirmAccessRightsButton()));
	accessRightsConfirmationLayout->addWidget(confirmAccessRightsButton);
	abbortAccessRightsButton = new QPushButton("Abbrechen");
	connect(abbortAccessRightsButton, SIGNAL(released()), this, SLOT(handleAbbortAccessRightsButton()));
	accessRightsConfirmationLayout->addWidget(abbortAccessRightsButton);
	accessRightsChoiceLayout->addLayout(accessRightsConfirmationLayout);
	
	testAccessRightsConfirmationLayout = new QHBoxLayout;
	testSelectAllAccessRightsButton = new QPushButton("Alles auswählen");
	connect(testSelectAllAccessRightsButton, SIGNAL(released()), this, SLOT(handleTestSelectAllAccessRightsButton()));
	testAccessRightsConfirmationLayout->addWidget(testSelectAllAccessRightsButton);
	testSelectSomeAccessRightsButton = new QPushButton("Ein Beispiel Auswählen");
	connect(testSelectSomeAccessRightsButton, SIGNAL(released()), this, SLOT(handleTestSelectSomeAccessRightsButton()));
	testAccessRightsConfirmationLayout->addWidget(testSelectSomeAccessRightsButton);
	accessRightsChoiceLayout->addLayout(testAccessRightsConfirmationLayout);

	accessRightsChoiceWidget->setLayout(accessRightsChoiceLayout);
}


void MainWindow::createActions() {

	helpAct = new QAction(tr("&Hilfe"), this);
	QList<QKeySequence> helpShortcuts;
	helpShortcuts.append(QKeySequence(Qt::CTRL + Qt::Key_H));
	helpAct->setShortcuts(helpShortcuts);
	helpAct->setStatusTip(tr("Wechselt in die Hilfe"));
	connect(helpAct, SIGNAL(triggered()), this, SLOT(showHelpWidget()));	

	pinAct = new QAction(tr("&Pin-Verwaltung"), this);
	QList<QKeySequence> pinShortcuts;
	pinShortcuts.append(QKeySequence(Qt::CTRL + Qt::Key_P));
	pinAct->setShortcuts(pinShortcuts);
	pinAct->setStatusTip(tr("Wechselt zur Pin-Verwaltung"));
	connect(pinAct, SIGNAL(triggered()), this, SLOT(showPinManagementWidget()));	

	testcaseAct = new QAction(tr("&Anbieter"), this);
	QList<QKeySequence> testcaseShortcuts;
	testcaseShortcuts.append(QKeySequence(Qt::CTRL + Qt::Key_A));
	testcaseAct->setShortcuts(testcaseShortcuts);
	testcaseAct->setStatusTip(tr("Wechselt zu den Testcases der Dienstanbieter"));
	connect(testcaseAct, SIGNAL(triggered()), this, SLOT(showTestcaseChoiceWidget()));


	accessRightsChoiceAct = new QAction(tr("&Zugriffsberechtigungen"), this);
	QList<QKeySequence> accessRightsShortcuts;
	accessRightsShortcuts.append(QKeySequence(Qt::CTRL + Qt::Key_Z));
	accessRightsChoiceAct->setShortcuts(accessRightsShortcuts);
	accessRightsChoiceAct->setStatusTip(tr("Wechselt zu der Auswahl der Zugriffsberichtigung"));
	connect(accessRightsChoiceAct, SIGNAL(triggered()), this, SLOT(showAccessRightsChoiceWidget()));

	eIDStatusAct = new QAction(tr("Log-eID&Status"), this);
	QList<QKeySequence> eIDStatusShortcuts;
	accessRightsShortcuts.append(QKeySequence(Qt::CTRL + Qt::Key_S));
	eIDStatusAct->setShortcuts(eIDStatusShortcuts);
	eIDStatusAct->setStatusTip(tr("Wechselt zu eID Status-Ausgabe"));
	connect(eIDStatusAct, SIGNAL(triggered()), this, SLOT(showEIDStatusWidget()));
	
	eIDOutputAct = new QAction(tr("Log-eID&Output"), this);
	QList<QKeySequence> eIDOutputShortcuts;
	accessRightsShortcuts.append(QKeySequence(Qt::CTRL + Qt::Key_O));
	eIDOutputAct->setShortcuts(eIDOutputShortcuts);
	eIDOutputAct->setStatusTip(tr("Wechselt zu eID Ergebnis-Ausgabe"));
	connect(eIDOutputAct, SIGNAL(triggered()), this, SLOT(showEIDOutputWidget()));

}


void MainWindow::createMainWidget() {
	mainWidget = new QWidget;
     	setCentralWidget(mainWidget);
	mainLayout = new QHBoxLayout;
	mainWidget->setLayout(mainLayout);
}

void MainWindow::createLogoWidget() {
	logoLayout = new QHBoxLayout;
	logoWidget = new QWidget;

	logoImage = new QPixmap("Logo_CMYK.tif");//better quality but too big todo resize 
	//logoImage = new QPixmap("Logo_RGB.gif");
	logoLabel = new QLabel(QString::fromUtf8("Hier könnte das Logo angezeigt werden."));
	//logoLabel->setPixmap(*logoImage);
	logoLabel->setPixmap(logoImage->scaledToHeight(200));
	logoLabel->setMaximumSize(250,250);//todo groeßer
	//logoLabel->resize(1200,800);//todo groeßer 

	logoLayout->setAlignment(Qt::AlignTop);
	logoLayout->addWidget(logoLabel);
	logoWidget->setLayout(logoLayout);
}

void MainWindow::createHelpWidget() {
	helpWidget = new QWidget;
	helpLayout = new QVBoxLayout;
	helpWidget->setLayout(helpLayout);
	helpTextLabel = new QLabel(QString::fromUtf8("Hier könnte die Hilfe oder ein Link zur Hilfe angezeigt werden."));
	helpLayout->addWidget(helpTextLabel);

}


void MainWindow::createMenus() {
	menuBar()->addAction(testcaseAct);
	menuBar()->addAction(pinAct);
	menuBar()->addAction(accessRightsChoiceAct);
	menuBar()->addAction(helpAct);
	menuBar()->addAction(eIDStatusAct);
	menuBar()->addAction(eIDOutputAct);
}

void MainWindow::createEIDOutputWidget() {
	eIDOutputWidget = new QWidget;
	eIDOutputLayout = new QVBoxLayout;
	eIDOutputWidget->setLayout(eIDOutputLayout);
	eIDOutputTextField = new QPlainTextEdit();
	eIDOutputTextField->setReadOnly(true);
	eIDOutputLayout->addWidget(eIDOutputTextField);	
}

void MainWindow::createPinManagementWidget() {
	pinManagementWidget = new QWidget;
	pinManagementLayout = new QVBoxLayout;
	pinManagementWidget->setLayout(pinManagementLayout);
	pinManagementLabel = new QLabel(QString::fromUtf8("Hier könnte die Funktionen zum Pin-Management angezeigt werden."));
	pinManagementLayout->addWidget(pinManagementLabel);
}

void MainWindow::createEIDStatusWidget() {
	eIDStatusWidget = new QWidget;
	eIDStatusLayout = new QVBoxLayout;
	eIDStatusWidget->setLayout(eIDStatusLayout);
	eIDStatusTextField = new QPlainTextEdit();
	eIDStatusTextField->setReadOnly(true);
	eIDStatusLayout->addWidget(eIDStatusTextField);	
}


void MainWindow::createTestcaseWidget() {
	testcaseChoiceWidget = new QWidget;
	testcaseChoiceLayout = new QVBoxLayout;
	testcaseChoiceWidget->setLayout(testcaseChoiceLayout);

	TestcaseAutentApp = "AutentApp";
	TestcaseNoSaml = "noSaml";
	TestcaseSaml1 = "Saml1";
	TestcaseSaml2 = "Saml2";
	TestcaseSelbstauskunftWuerzburg = "Selbstauskunft Würzburg";

	testcaseLabel = new QLabel(QString::fromUtf8("Bitte den Testcase auswählen:"));
	
	testcaseCombo = new QComboBox;
 	testcaseCombo->addItem(TestcaseAutentApp);
	testcaseCombo->addItem(TestcaseNoSaml);
	testcaseCombo->addItem(TestcaseSaml1);
	testcaseCombo->addItem(TestcaseSaml2);
	testcaseCombo->addItem(TestcaseSelbstauskunftWuerzburg);

	startTestcaseButton = new QPushButton("Starten");
	//set size and location of the button
	startTestcaseButton->setGeometry(QRect(QPoint(100, 100),
	                             QSize(200, 50)));
	//Connect startTestcaseButton signal to appropriate slot
	connect(startTestcaseButton, SIGNAL(released()), this, SLOT(handleTestcaseButton()));

	testcaseChoiceLayout->addWidget(testcaseLabel);
	testcaseChoiceLayout->addWidget(testcaseCombo);
	testcaseChoiceLayout->addWidget(startTestcaseButton);
}

void MainWindow::setAccessRightsRadioButtonMandatory(QRadioButton *rb) {
	rb->setVisible(true);
	rb->setEnabled(false);
	rb->setChecked(true);
}
void MainWindow::setAccessRightsRadioButtonNotRequested(QRadioButton *rb) {
	rb->setVisible(false);
	//rb->setEnabled(false);	
}
void MainWindow::setAccessRightsRadioButtonOptional(QRadioButton *rb) {
	rb->setVisible(true);
	rb->setEnabled(true);
	rb->setChecked(true);//todo Policy matter to discuss	
}

//todo implement one show*Widget function, because there is to much redundancy for all functions

void MainWindow::showAccessRightsChoiceWidget() {
	int index = applicationStackedWidget->indexOf(accessRightsChoiceWidget);
	if(index == -1) {
		qFatal("ERROR accessRightsWidget not initialized or not added to applicationStackedWidget: %i, in %s \n", __LINE__, __FILE__);
	}
	else {
		applicationStackedWidget->setCurrentIndex(index);
	}
}

void MainWindow::showEIDOutputWidget() {
	int index = applicationStackedWidget->indexOf(eIDOutputWidget);
	if(index == -1) {
		qFatal("ERROR accessRightsWidget not initialized or not added to applicationStackedWidget: %i, in %s \n", __LINE__, __FILE__);
	}
	else {
		applicationStackedWidget->setCurrentIndex(index);
	}
}

void MainWindow::showEIDStatusWidget() {
	int index = applicationStackedWidget->indexOf(eIDStatusWidget);
	if(index == -1) {
		qFatal("ERROR accessRightsWidget not initialized or not added to applicationStackedWidget: %i, in %s \n", __LINE__, __FILE__);
	}
	else {
		applicationStackedWidget->setCurrentIndex(index);
	}
}

void MainWindow::showHelpWidget() {
	int index = applicationStackedWidget->indexOf(helpWidget);
	if(index == -1) {
		qFatal("ERROR helpWidget not initialized or not added to applicationStackedWidget: %i, in %s \n", __LINE__, __FILE__);
	}
	else {
		applicationStackedWidget->setCurrentIndex(index);
	}
}

void MainWindow::showPinManagementWidget() {
	int index = applicationStackedWidget->indexOf(pinManagementWidget);
	if(index == -1) {
		qFatal("ERROR pinManagementWidget not initialized or not added to applicationStackedWidget: %i, in %s \n", __LINE__, __FILE__);
	}
	else {
		applicationStackedWidget->setCurrentIndex(index);
	}
}

void MainWindow::showTestcaseChoiceWidget() {
	int index = applicationStackedWidget->indexOf(testcaseChoiceWidget);
	if(index == -1) {
		qFatal("ERROR testcaseWidget not initialized or not added to applicationStackedWidget: %i, in %s \n", __LINE__, __FILE__);
	}
	else {
		applicationStackedWidget->setCurrentIndex(index);
	}
}

//function for testing the AccessRightsRadioButtons
void MainWindow::simulateInitAccessRightsRadioButtonsExample() {

	printf("test simulateInitAccessRightsRadio.... ,  %i , %s \n", __LINE__, __FILE__);
	setAccessRightsRadioButtonMandatory(issuingCountryRadioButton);
	setAccessRightsRadioButtonMandatory(documentTypeRadioButton);
	setAccessRightsRadioButtonMandatory(issuingCountryRadioButton);
	setAccessRightsRadioButtonMandatory(validUntilRadioButton);
	setAccessRightsRadioButtonOptional(givenNameRadioButton);
	setAccessRightsRadioButtonOptional(familyNameRadioButton);
	setAccessRightsRadioButtonOptional(religiousOrArtisticalNameRadioButton);
	setAccessRightsRadioButtonOptional(doctoralDegreeRadioButton);
	setAccessRightsRadioButtonOptional(birthDateRadioButton);
	setAccessRightsRadioButtonOptional(birthPlaceRadioButton);
	setAccessRightsRadioButtonOptional(nationalityRadioButton);
	setAccessRightsRadioButtonOptional(birthNameRadioButton);
	setAccessRightsRadioButtonNotRequested(adressRadioButton);
	setAccessRightsRadioButtonNotRequested(auxConditionsRadioButton);
	setAccessRightsRadioButtonNotRequested(pseudonymRadioButton);
	setAccessRightsRadioButtonNotRequested(verificationAdressRadioButton);
	setAccessRightsRadioButtonNotRequested(verificationAgeRadioButton);
}

//function for testing the AccessRightsRadioButtons
void MainWindow::simulateInitAccessRightsRadioButtonsAllOptional() {
	setAccessRightsRadioButtonOptional(issuingCountryRadioButton);
	setAccessRightsRadioButtonOptional(documentTypeRadioButton);
	setAccessRightsRadioButtonOptional(issuingCountryRadioButton);
	setAccessRightsRadioButtonOptional(validUntilRadioButton);
	setAccessRightsRadioButtonOptional(givenNameRadioButton);
	setAccessRightsRadioButtonOptional(familyNameRadioButton);
	setAccessRightsRadioButtonOptional(religiousOrArtisticalNameRadioButton);
	setAccessRightsRadioButtonOptional(doctoralDegreeRadioButton);
	setAccessRightsRadioButtonOptional(birthDateRadioButton);
	setAccessRightsRadioButtonOptional(birthPlaceRadioButton);
	setAccessRightsRadioButtonOptional(nationalityRadioButton);
	setAccessRightsRadioButtonOptional(birthNameRadioButton);
	setAccessRightsRadioButtonOptional(adressRadioButton);
	setAccessRightsRadioButtonOptional(auxConditionsRadioButton);
	setAccessRightsRadioButtonOptional(pseudonymRadioButton);
	setAccessRightsRadioButtonOptional(verificationAdressRadioButton);
	setAccessRightsRadioButtonOptional(verificationAgeRadioButton);
}


NPACLIENT_ERROR MainWindow::nPAeIdUserInteractionCallback(
	const SPDescription_t *description, UserInput_t *input)
{
	printf("nPAeIdUserInteractionCallback called %i, in %s \n", __LINE__, __FILE__);	

	QString output;
	MainWindow::getInstance()->eIDStatusTextField->insertPlainText(output);

	if (input->pin_required) {
		strncpy((char *) input->pin.pDataBuffer, gPin.data(), gPin.length());
		input->pin.bufferSize = gPin.length();
	}

#define MAX(a,b) (a>b ? a : b)
	char buf[1024];

	snprintf(buf, MAX(sizeof buf, description->name.bufferSize), (char *) description->name.pDataBuffer);
	buf[(sizeof buf) - 1] = '\0';
	printf("serviceName: %s\n", buf);
	MainWindow::getInstance()->serviceProviderLabel->setText(QString(buf));

	snprintf(buf, MAX(sizeof buf, description->url.bufferSize), (char *) description->url.pDataBuffer);
	buf[(sizeof buf) - 1] = '\0';
	printf("serviceURL:  %s\n", buf);
	

	snprintf(buf, MAX(sizeof buf, description->description.bufferSize), (char *) description->description.pDataBuffer);
	buf[(sizeof buf) - 1] = '\0';	
	printf("certificateDescription:\n%s\n", buf);
	MainWindow::getInstance()->certificateDescription=QString(buf);

	//todo parse purpose of use from the certificate description
	MainWindow::getInstance()->purposeOfUseLabel->setText("siehe Beschreibung");

	
	MainWindow::getInstance()->showEIDStatusWidget();

	if(description->transactionInfo.bufferSize > 0)
	{
		snprintf(buf, MAX(sizeof buf, description->transactionInfo.bufferSize), (char *) description->transactionInfo.pDataBuffer);
		buf[(sizeof buf) - 1] = '\0';
		printf("TransactionInfo:\n%s\n", buf);
	}
	if(description->transactionInfoHidden.bufferSize > 0)
	{
		snprintf(buf, MAX(sizeof buf, description->transactionInfoHidden.bufferSize), (char *) description->transactionInfoHidden.pDataBuffer);
		buf[(sizeof buf) - 1] = '\0';
		printf("TransactionInfoHidden:\n%s\n", buf);
	}

	switch (description->chat_required.type) {
		case TT_IS:
			eIDStatusTextFieldAppend("Inspection System:");
			if (description->chat_required.authorization.is.read_finger 	) eIDStatusTextFieldAppend("\tRead Fingerprint");
			if (description->chat_required.authorization.is.read_iris  	) eIDStatusTextFieldAppend("\tRead Iris");
			if (description->chat_required.authorization.is.read_eid	) eIDStatusTextFieldAppend("\tRead eID");
			break;

		case TT_AT:
			eIDStatusTextFieldAppend("Authentication Terminal:");
			if (description->chat_required.authorization.at.age_verification			) eIDStatusTextFieldAppend("\tVerify Age");
			if (description->chat_required.authorization.at.community_id_verification 		) eIDStatusTextFieldAppend("\tVerify Community ID");
			if (description->chat_required.authorization.at.restricted_id 				) eIDStatusTextFieldAppend("\tRestricted ID");
			if (description->chat_required.authorization.at.privileged 				) eIDStatusTextFieldAppend("\tPrivileged Terminal");
			if (description->chat_required.authorization.at.can_allowed 				) eIDStatusTextFieldAppend("\tCAN allowed");
			if (description->chat_required.authorization.at.pin_management 				) eIDStatusTextFieldAppend("\tPIN Management");
			if (description->chat_required.authorization.at.install_cert 				) eIDStatusTextFieldAppend("\tInstall Certificate");
			if (description->chat_required.authorization.at.install_qualified_cert 			) eIDStatusTextFieldAppend("\tInstall Qualified Certificate");
//############################################################################
//Chat
//
///example autentapp:
//	Read Document Type
//	Read Issuing State
//	Read Given Names
//	Read Family Names
//	Read Religious/Artistic Name
//	Read Academic Title
//	Read Date of Birth
//	Read Place of Birth
//	Read Nationality
//	Read DG 13						--not set
//	Read Normal Place of Residence 		-- Anschrift	
//	Read Residence Permit I					--not set
			if (description->chat_required.authorization.at.read_dg1	) {
				eIDStatusTextFieldAppend("\tRead Document Type");
				MainWindow::getInstance()->setAccessRightsRadioButtonMandatory(MainWindow::getInstance()->documentTypeRadioButton);
			}
			else {
				MainWindow::getInstance()->setAccessRightsRadioButtonNotRequested(MainWindow::getInstance()->documentTypeRadioButton);
			}
			if (description->chat_required.authorization.at.read_dg2        ) {
				eIDStatusTextFieldAppend("\tRead Issuing State");
				MainWindow::getInstance()->setAccessRightsRadioButtonMandatory(MainWindow::getInstance()->issuingCountryRadioButton);
			}
			else {
				MainWindow::getInstance()->setAccessRightsRadioButtonNotRequested(MainWindow::getInstance()->issuingCountryRadioButton);
			}
			if (description->chat_required.authorization.at.read_dg3      	) {
				eIDStatusTextFieldAppend("\tRead Date of Expiry");
				MainWindow::getInstance()->setAccessRightsRadioButtonMandatory(MainWindow::getInstance()->validUntilRadioButton);
			}
			else {
				MainWindow::getInstance()->setAccessRightsRadioButtonNotRequested(MainWindow::getInstance()->validUntilRadioButton);
			}
			if (description->chat_required.authorization.at.read_dg4	) {
				eIDStatusTextFieldAppend("\tRead Given Names");
				MainWindow::getInstance()->setAccessRightsRadioButtonMandatory(MainWindow::getInstance()->givenNameRadioButton);
			}
			else {
				MainWindow::getInstance()->setAccessRightsRadioButtonNotRequested(MainWindow::getInstance()->givenNameRadioButton);
			}
			if (description->chat_required.authorization.at.read_dg5	) {
				eIDStatusTextFieldAppend("\tRead Family Names");
				MainWindow::getInstance()->setAccessRightsRadioButtonMandatory(MainWindow::getInstance()->familyNameRadioButton);				
			}
			else {
				MainWindow::getInstance()->setAccessRightsRadioButtonNotRequested(MainWindow::getInstance()->familyNameRadioButton);
			}
			if (description->chat_required.authorization.at.read_dg6	) {
				eIDStatusTextFieldAppend("\tRead Religious/Artistic Name");
				MainWindow::getInstance()->setAccessRightsRadioButtonMandatory(MainWindow::getInstance()->religiousOrArtisticalNameRadioButton);
			}
			else {
				MainWindow::getInstance()->setAccessRightsRadioButtonNotRequested(MainWindow::getInstance()->religiousOrArtisticalNameRadioButton);
			}
			if (description->chat_required.authorization.at.read_dg7	) {
				eIDStatusTextFieldAppend("\tRead Academic Title");	
				MainWindow::getInstance()->setAccessRightsRadioButtonMandatory(MainWindow::getInstance()->doctoralDegreeRadioButton);
			}
			else {
				MainWindow::getInstance()->setAccessRightsRadioButtonNotRequested(MainWindow::getInstance()->doctoralDegreeRadioButton);
			}
			if (description->chat_required.authorization.at.read_dg8 	) {
				eIDStatusTextFieldAppend("\tRead Date of Birth");
				MainWindow::getInstance()->setAccessRightsRadioButtonMandatory(MainWindow::getInstance()->birthDateRadioButton);
			}
			else {
				MainWindow::getInstance()->setAccessRightsRadioButtonNotRequested(MainWindow::getInstance()->birthDateRadioButton);
			}
			if (description->chat_required.authorization.at.read_dg9        ) {
				eIDStatusTextFieldAppend("\tRead Place of Birth");
				MainWindow::getInstance()->setAccessRightsRadioButtonMandatory(MainWindow::getInstance()->birthPlaceRadioButton);
			}
			else {
				MainWindow::getInstance()->setAccessRightsRadioButtonNotRequested(MainWindow::getInstance()->birthPlaceRadioButton);
			}
			if (description->chat_required.authorization.at.read_dg10	) {
				eIDStatusTextFieldAppend("\tRead Nationality");
				MainWindow::getInstance()->setAccessRightsRadioButtonMandatory(MainWindow::getInstance()->nationalityRadioButton);
			}
			else {
				MainWindow::getInstance()->setAccessRightsRadioButtonNotRequested(MainWindow::getInstance()->nationalityRadioButton);
			}
			if (description->chat_required.authorization.at.read_dg11     				) eIDStatusTextFieldAppend("\tRead Sex");//todo
			if (description->chat_required.authorization.at.read_dg12				) eIDStatusTextFieldAppend("\tRead OptionalDataR");//todo
			if (description->chat_required.authorization.at.read_dg13				) eIDStatusTextFieldAppend("\tRead DG 13");//todo
			if (description->chat_required.authorization.at.read_dg14				) eIDStatusTextFieldAppend("\tRead DG 14");//todo
			if (description->chat_required.authorization.at.read_dg15				) eIDStatusTextFieldAppend("\tRead DG 15");//todo
			if (description->chat_required.authorization.at.read_dg16				) eIDStatusTextFieldAppend("\tRead DG 16");//todo
			if (description->chat_required.authorization.at.read_dg17       ) {
				eIDStatusTextFieldAppend("\tRead Normal Place of Residence");
				MainWindow::getInstance()->setAccessRightsRadioButtonMandatory(MainWindow::getInstance()->adressRadioButton);
			}
			else {
				MainWindow::getInstance()->setAccessRightsRadioButtonNotRequested(MainWindow::getInstance()->adressRadioButton);
			}
			if (description->chat_required.authorization.at.read_dg18             			) eIDStatusTextFieldAppend("\tRead Community ID");//todo
			if (description->chat_required.authorization.at.read_dg19     				) eIDStatusTextFieldAppend("\tRead Residence Permit I");//todo
			if (description->chat_required.authorization.at.read_dg20	) {
				eIDStatusTextFieldAppend("\tRead Residence Permit II");//todo
			}
//#############################################################################
			if (description->chat_required.authorization.at.read_dg21				) eIDStatusTextFieldAppend("\tRead OptionalDataRW");
			if (description->chat_required.authorization.at.write_dg21				) eIDStatusTextFieldAppend("\tWrite OptionalDataRW");
			if (description->chat_required.authorization.at.write_dg20        			) eIDStatusTextFieldAppend("\tWrite Residence Permit I");
			if (description->chat_required.authorization.at.write_dg19                		) eIDStatusTextFieldAppend("\tWrite Residence Permit II");
			if (description->chat_required.authorization.at.write_dg18    				) eIDStatusTextFieldAppend("\tWrite Community ID");
			if (description->chat_required.authorization.at.write_dg17				) eIDStatusTextFieldAppend("\tWrite Normal Place of Residence");
			break;

		case TT_ST:
			eIDStatusTextFieldAppend("Signature Terminal:");
			if (description->chat_required.authorization.st.generate_signature 				) eIDStatusTextFieldAppend("\tGenerate electronic signature");
			if (description->chat_required.authorization.st.generate_qualified_signature 	) eIDStatusTextFieldAppend("\tGenerate qualified electronic signature");
			break;

		default:
			printf("%s:%d: Error\n", __FILE__, __LINE__);
	}

	input->chat_selected = description->chat_required;

	return NPACLIENT_ERROR_SUCCESS;
}

void MainWindow::nPAeIdProtocolStateCallback(const NPACLIENT_STATE state, const NPACLIENT_ERROR error)
{
	printf("nPAeIdProtocolStateCallback called %i, in %s \n", __LINE__, __FILE__);
	printf("nPAeIdProtocolStateCallback state: %lu   %i, in %s \n", state, __LINE__, __FILE__);
	printf("nPAeIdProtocolStateCallback error: %lu   %i, in %s \n", error, __LINE__, __FILE__);

	eIDStatusTextFieldAppend(
		"nPAeIdProtocolStateCallback called " +
		QString::number(__LINE__) +
		", in " + __FILE__ + "\n");
	gError = error;
	switch(state)
	{
	case NPACLIENT_STATE_INITIALIZE:
		if(error == NPACLIENT_ERROR_SUCCESS)
		{
			eIDStatusTextFieldAppend("nPA client successful initialized");
		}
		else
		{
			//mutex_unlock(ghMutex);
			//errorOut("nPA client initialisation failed (0x%08lX)", error);
			eIDStatusTextFieldAppend("nPA client initialisation failed", error);
		}
		break;
	case NPACLIENT_STATE_GOT_PACE_INFO:
		if(error == NPACLIENT_ERROR_SUCCESS)
		{
			eIDStatusTextFieldAppend("nPA client got PACE info successfully");
		}
		else
		{
			//mutex_unlock(ghMutex);
			eIDStatusTextFieldAppend("nPA client got PACE info failed", error);
		}
		break;
	case NPACLIENT_STATE_PACE_PERFORMED:
		if(error == NPACLIENT_ERROR_SUCCESS)
		{
			eIDStatusTextFieldAppend("nPA client perfomed PACE successfully");
		}
		else
		{
			//mutex_unlock(ghMutex);
			eIDStatusTextFieldAppend("nPA client perform PACE failed", error);
		}
		break;
	case NPACLIENT_STATE_TA_PERFORMED:
		if(error == NPACLIENT_ERROR_SUCCESS)
		{
			eIDStatusTextFieldAppend("nPA client perfomed TA successfully");
		}
		else
		{
			//mutex_unlock(ghMutex);
			eIDStatusTextFieldAppend("nPA client perform TA failed", error);
		}
		break;
	case NPACLIENT_STATE_CA_PERFORMED:
		if(error == NPACLIENT_ERROR_SUCCESS)
		{
			eIDStatusTextFieldAppend("nPA client perfomed CA successfully");
		}
		else
		{
			//mutex_unlock(ghMutex);
			eIDStatusTextFieldAppend("nPA client perform CA failed", error);
		}
		break;
	case NPACLIENT_STATE_READ_ATTRIBUTES:
		if(error == NPACLIENT_ERROR_SUCCESS)
		{
			//mutex_unlock(ghMutex);
			eIDStatusTextFieldAppend("nPA client read attribute successfully\n\n");
		}
		else
		{
			//mutex_unlock(ghMutex);
			eIDStatusTextFieldAppend("nPA client read attributes failed" ,error);
		}
		break;
	default:
		break;
	}
}

void MainWindow::eIDStatusTextFieldAppend(const QString msg) {
	MainWindow::getInstance()->eIDStatusTextField->insertPlainText(msg + "\n");
}

void MainWindow::eIDStatusTextFieldAppend(const QString msg, const NPACLIENT_ERROR error) {
	eIDStatusTextFieldAppend(msg + QString(" (0x%1)").arg(error,8,16, QLatin1Char('0')));
}

void MainWindow::createSimpleClientThread() {
	//todo IMPORTANT: QThread instead of std::thread to avoid unexpected segmentation faults
	std::thread simpleClientThread (startSimpleClient, nPAeIdUserInteractionCallback, nPAeIdProtocolStateCallback);
	simpleClientThread.detach();
}

