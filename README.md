# Welcome

All relevant information about the eIDClientCore can be found at:
http://sar.informatik.hu-berlin.de/BeID-lab/eIDClientCore

Warning: This is just proof-of-concept code and should _NOT_ be used in
production environments

## TODO
* Add abstraction layer between ePACard and cryptographic functions
* Maybe remove ICardDetector and use ICard constructor instead to determine the card's type
* Use good namespaces
* Check try...catch block around C-Interfaces
* use OOP in nPA-EAC
* Check the hash of the SSL/TLS certificate from the SP with the SP's Terminal certificate
* Check if the Terminal certificate is up to date
* Check the Subject URL of the Terminal certificate
