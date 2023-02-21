#include <iostream>
#include <vector>

using namespace std;

class Transaction {
    public:
      Transaction(int amount) : amount(amount) {}
      int getAmount() const { return amount; }

    private:
      int amount;
};

class Wallet { 
    protected:
        float balance_;
        std::string privateKey_;

    private:
        std::vector<Transaction> transactions;
        static Wallet* inst_;   // The one, single instance
        Wallet() : balance_(0) {
            privateKey_ = "01234";
        }

        Wallet(const Wallet&);
        Wallet& operator=(const Wallet&);

    public:
        // This is how clients can access the single instance
        static Wallet* getInstance();

        void setBalance(float balance) {balance_ = balance;}
        float getBalance()           {return(balance_);}

        void setPrivateKey(std::string privateKey) {privateKey_ = privateKey;}
        std::string getPrivateKey()       {return(privateKey_);} 

        void addTransaction(const Transaction &t) {
            transactions.push_back(t);
        }


        void sendMoney(float amount, std::string recipientAddress) {
            // Check that current wallet has enough money to send the funds
            if (amount > balance_) {
                std::cout << "Not enough funds." << std::endl;
            } else {
        // TODO: Deal with keys before allowing amount to be sent (where send, what keys needed)
            // Create public key (think of it like an account number), represented by bitcoin address
                // Create unique public based on set private
                    // Add each public key to array (keep track of them), have it be 2D array that also keeps counter to identify
                    // which transaction number this is used for
            // If all checks out with keys, then "send" so subtract from balance
                balance_ -= amount;
            // Later will wait until confirmation that transaction was received
            // For now, just check that public key created
              // Update balance --> new balance = current balance - transaction amount
            } 
        }

    // Create incoming transaction
        void receiveMoney(float amount, std::string senderAddress) {
            // Get public key
        // Use public key on transaction
            // Get transaction ID number (or maybe give)
            // Get transaction amount
    // If info successfully gotten, update balance
            balance_ += amount;
        // Later will send back confirmation that transaction was received
        // For now, just check that public key was able to get information
            // Update balance --> new balance = current balance + transaction amount

        }
    };

// Define the static Wallet pointer
Wallet* Wallet::inst_ = NULL;

Wallet* Wallet::getInstance() {
   if (inst_ == NULL) {
      inst_ = new Wallet();
   }
   return(inst_);
}

int main() {

    Transaction* transactions = new Transaction(10);

    Wallet* p1 = Wallet::getInstance();
    p1->setBalance(10);
    Wallet* p2 = Wallet::getInstance();
    cout << "Balance = " << p2->getBalance() << '\n';

    // Transaction history
    size_t n = sizeof(transactions)/sizeof(transactions[0]);
    for (size_t i = 0; i < n; i++) {
        std::cout << transactions[i] << ' ';
    }
    return 0;
}
