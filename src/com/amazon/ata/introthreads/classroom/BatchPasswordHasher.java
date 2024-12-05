package com.amazon.ata.introthreads.classroom;

import com.google.common.collect.Maps;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

// immutable:
// (1) make the class final
// (2) make the instance variables final
// (3) check the constructors for reference parameters, make sure they're a defensive copy
// (4) check any instance variables that are returned, be sure that they're returned by
//     reference
// (5) should have no setters (because it's immutable)

// <Runnable> or <Thread>:
// - we are implementing <Runnable> instead of extending <Thread> in case this needs to be a
//   subclass one day

/**
 * A class to hash a batch of passwords in a separate thread.
 */
public final class BatchPasswordHasher implements Runnable {
// this class needs to be modified to be able to run concurrently
// (1) ensure that the class is immutable
// (2) make it either <Runnable> or a subclass of <Thread>

    private final List<String> passwords;
    private final Map<String, String> passwordToHashes;
    private final String salt;

    public BatchPasswordHasher(List<String> passwords, String salt) {
        // this.passwords = passwords;
        this.passwords = new ArrayList<>(passwords);
        // not hard to do a defensive copy
        this.salt = salt;
        passwordToHashes = new HashMap<>();
    }
    // constructor receives a reference to a list, defensive copy it to instance variable

    /**
     *  Hashes all the passwords, and stores the hashes in the passwordToHashes Map.
     */
    public void hashPasswords() {
        try {
            for (String password : passwords) {
                final String hash = PasswordUtil.hash(password, salt);
                passwordToHashes.put(password, hash);
            }
            System.out.println(String.format("Completed hashing batch of %d passwords.", passwords.size()));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * Returns a map where the key is a plain text password and the key is the hashed version of the plaintext password
     * and the class' salt value.
     *
     * @return passwordToHashes - a map of passwords to their hash value.
     */
    public Map<String, String> getPasswordToHashes() {
        Map<String, String> newMap = new HashMap<>();
        newMap.putAll(passwordToHashes);
        return newMap;
        // this could have all been done in a single statement
    }
    // since we are returning a reference to an instance variable, we should defensive
    //  return it

    @Override
    public void run() {
        hashPasswords();
    }
    // this method is required by the <Runnable> interface
    // the run() method is what is run when this process is a <Thread>
    //  like main() in a java app or handleRequest() in an aws function

    // you can use inheritance to make your process concurrently executable by extending the
    //  <thread> class, or you can do it by implementing the <Runnable> interface
    // the reason most people choose <Runnable> is because you can then be a subclass of
    //  something else, java only allows you to be a subclass of one other class
    // if you make yourself a subclass of <Thread> you can't be a subclass of anything else
    //  which you probably need to be
    // there's a lot more flexibility if you implement <Runnable> because then you can be a
    //  subclass of anything else
}
