package com.amazon.ata.introthreads.classroom;

import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVPrinter;

import java.io.BufferedWriter;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * A class to pre-compute hashes for all common passwords to speed up cracking the hacked
 * database.
 *
 * Passwords are downloaded from
 * https://github.com/danielmiessler/SecLists/tree/master/Passwords/Common-Credentials
 */
public class PasswordHasher {
// should create the file in your workspace directory

    private static final String PASSWORDS_AND_HASHES_FILE = "./passwordsAndHashesOutput.csv";
    private static final String DISCOVERED_SALT = "salt";
    // a "salt" is a value included in the hashing/encrypting process to make it to de-hash/
    //  de-crypt the value
    // normally a "salt" is a long string of random values - 64, 128, 512, 1024, 2048
    //  character salts ... the longer the salt, the harder it is to de-crypt
    // this is a bad salt ... it's a constant and short

    /**
     * Generates hashes for all the given passwords.
     *
     * @param passwords List of passwords to hash
     * @return map of password to hash
     * @throws InterruptedException
     */
    public static Map<String, String> generateAllHashes(List<String> passwords) throws
            InterruptedException {
        Map<String, String> passwordToHashes = Maps.newConcurrentMap();
        // going to hold the final result of all the hashed passwords

//        BatchPasswordHasher batchHasher =
//                new BatchPasswordHasher(passwords, DISCOVERED_SALT);
//        batchHasher.hashPasswords();
//        passwordToHashes.putAll(batchHasher.getPasswordToHashes());
        // going to replace the call and processing to a single BatchPasswordHasher() to
        // multi-threaded, concurrent calls

        List<List<String>> passwordSubLists =
                Lists.partition(passwords, passwords.size() / 4);
        // split the list of passwords into sub lists to give to each thread
        // we'll have 4 threads

        List<BatchPasswordHasher> savedHashers = new ArrayList<>();

        List<Thread> theThreads = new ArrayList<>();
        // since a Thread is destroyed when it's done, and we need to wait for all Threads
        //  to complete before we can merge the results
        // we will store or save the Threads, so we can reference them in the
        //  waitForThreadsToComplete() method

        for (int i = 0; i < passwordSubLists.size(); i++) {
            BatchPasswordHasher aHasher =
                    new BatchPasswordHasher(passwordSubLists.get(i), DISCOVERED_SALT);
            // instantiate a BatchPasswordHasher with a sub list

            savedHashers.add(aHasher);
            // since the hashed passwords are inside the BatchPasswordHasher and the
            //  BatchPasswordHasher will be destroyed when the Thread completes
            // we will store/save each BatchPasswordHasher, so it will exist when the Thread
            //  is done
            // the reason we need that is so that we can copy its hashed passwords to our
            //  final result set of hashed passwords

            Thread aThread = new Thread(aHasher);
            // instantiate a thread for the BatchPasswordHasher

            theThreads.add(aThread);
            // save the Thread in a list, so we can send to watForThreadsToComplete() method

            aThread.start();
            // start the Thread, so it will begin running
            // execution in this process continues
            // we do not wait for the Thread to complete
        }
        // loop through the sub lists of passwords and start a BatchPasswordHasher for each
        //  one

        // when a Thread dies all of its data dies too along with it

        waitForThreadsToComplete(theThreads);
        // now that all the threads have been started - we'll wait for them to complete

        for (BatchPasswordHasher aHasher : savedHashers) {
            passwordToHashes.putAll(aHasher.getPasswordToHashes());
            // copy all the Map entries to the result
        }
        // so now all Threads are complete, each BatchPasswordHasher has its hashed
        //  passwords
        // all that's left to do is merge the hashed passwords from each BatchPasswordHasher
        //  into the final result

        return passwordToHashes;
        // return the final result
    }

    /**
     * Makes the thread calling this method wait until passed in threads are done executing before proceeding.
     *
     * @param threads to wait on
     * @throws InterruptedException
     */
    public static void waitForThreadsToComplete(List<Thread> threads) throws
            InterruptedException {
        for (Thread thread : threads) {
            thread.join();
            // waits for the current Thread to complete/die
            // horrible name, doesn't join anything ... this waits for the current Thread
            //  to complete
        }
        // loop through the list of threads we're given, and we're going to wait for each one
        //  to finish
    }

    /**
     * Writes pairs of password and its hash to a file.
     */
    static void writePasswordsAndHashes(Map<String, String> passwordToHashes) {
        File file = new File(PASSWORDS_AND_HASHES_FILE);
        try (
            BufferedWriter writer = Files.newBufferedWriter(file.toPath());
            CSVPrinter csvPrinter = new CSVPrinter(writer, CSVFormat.DEFAULT)
        ) {
            for (Map.Entry<String, String> passwordToHash : passwordToHashes.entrySet()) {
                final String password = passwordToHash.getKey();
                final String hash = passwordToHash.getValue();

                csvPrinter.printRecord(password, hash);
            }
            System.out.println("Wrote output of batch hashing to "
                    + file.getAbsolutePath());
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

}
