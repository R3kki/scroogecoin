import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;

public class TxHandler {

    /**
     * Creates a public ledger whose current UTXOPool (collection of unspent transaction outputs) is
     * {@code utxoPool}. This should make a copy of utxoPool by using the UTXOPool(UTXOPool uPool)
     * constructor.
     */

    private final UTXOPool currentPool;

    public TxHandler(UTXOPool utxoPool) {
        currentPool = new UTXOPool(utxoPool);
    }

    /**
     * @return true if:
     * (1) all inputs (prev Pool outputs) claimed by {@code tx} are in the current UTXO pool,
     * (2) the signatures on each input of {@code tx} are valid,
     * (3) no UTXO is claimed multiple times by {@code tx},
     * (4) all of {@code tx}s output values are non-negative, and
     * (5) the sum of {@code tx}s input values is greater than or equal to the sum of its output
     * values; and false otherwise.
     */
    public boolean isValidTx(Transaction tx) {
        if (tx == null) return false;
        HashSet<UTXO> claimedUnspentOutputs = new HashSet<>();
        double inputSum = 0, outputSum = 0;

        // (1, 2, 3)
        for (int i = 0; i < tx.numInputs(); i++) {
            Transaction.Input input = tx.getInput(i);
            if (input == null) return false;


            byte[] hash = input.prevTxHash;
            int index = input.outputIndex;
            byte[] signature = input.signature;

            UTXO utxo = new UTXO(hash, index);
            if (!currentPool.contains(utxo)) return false; // (1)

            Transaction.Output prevOutput = currentPool.getTxOutput(utxo);
            PublicKey pubKey = prevOutput.address;
            byte[] message = tx.getRawDataToSign(i); // i and not input.OutputIndex
            if (!Crypto.verifySignature(pubKey, message, signature)) return false; // (2)

            if (claimedUnspentOutputs.contains(utxo)) return false; // (3)
            claimedUnspentOutputs.add(utxo);

            inputSum += prevOutput.value; // (5) input
        }
        // (4, 5)
        for (int i = 0; i < tx.numOutputs(); i++) {
            Transaction.Output output = tx.getOutput(i);
            if (output.value < 0) return false; // (4)
            outputSum += output.value; // (5) output
        }
        return (inputSum >= outputSum); // (5)
    }

    /**
     * Handles each epoch by receiving an unordered array of proposed transactions, checking each
     * transaction for correctness, returning a mutually valid array of accepted transactions, and
     * updating the current UTXO pool as appropriate.
     */
    public Transaction[] handleTxs(Transaction[] possibleTxs) {
        ArrayList<Transaction> validTransactions = new ArrayList<>();

        // validate and add keep track of accepted transactions
        for (Transaction t : possibleTxs)
            if (isValidTx(t)) validTransactions.add(t);

        // update current UTXO pool
        int index = 0;
        Transaction[] acceptedTransactions = new Transaction[validTransactions.size()];
        for (Transaction t : validTransactions) {
            acceptedTransactions[index++] = t;
            byte[] txHash = t.getHash();
            // update the transaction outputs
            int txIndex = 0;
            for (Transaction.Output output : t.getOutputs()) {
                UTXO ut = new UTXO(txHash, txIndex++);
                currentPool.addUTXO(ut, output); // add to current UTXO Pool
            }
        }

        return acceptedTransactions;

    }

}
