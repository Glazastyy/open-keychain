package org.sufficientlysecure.keychain.daos;


import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import android.content.Context;

import org.sufficientlysecure.keychain.KeychainDatabase;
import org.sufficientlysecure.keychain.UidStatus;
import org.sufficientlysecure.keychain.model.UserId;


public class UserIdDao extends AbstractDao {
    public static UserIdDao getInstance(Context context) {
        KeychainDatabase keychainDatabase = KeychainDatabase.getInstance(context);
        DatabaseNotifyManager databaseNotifyManager = DatabaseNotifyManager.create(context);

        return new UserIdDao(keychainDatabase, databaseNotifyManager);
    }

    private UserIdDao(KeychainDatabase db, DatabaseNotifyManager databaseNotifyManager) {
        super(db, databaseNotifyManager);
    }

    public List<UserId> getUserIdsByMasterKeyIds(long... masterKeyIds) {
        return getDatabase().getUserPacketsQueries()
                .selectUserIdsByMasterKeyId(getLongArrayAsList(masterKeyIds), UserId::create)
                .executeAsList();
    }

    public Map<String, UidStatus> getUidStatusByEmail(String... emails) {
        List<UidStatus> items = getDatabase().getUserPacketsQueries()
                .selectUserIdStatusByEmail(Arrays.asList(emails))
                .executeAsList();
        return toStatusByEmailMap(items);
    }

    public Map<String, UidStatus> getUidStatusByEmailLike(String query) {
        List<UidStatus> items = getDatabase().getUserPacketsQueries()
                .selectUserIdStatusByEmailLike(query)
                .executeAsList();
        return toStatusByEmailMap(items);
    }

    private static Map<String, UidStatus> toStatusByEmailMap(List<UidStatus> items) {
        Map<String, UidStatus> result = new HashMap<>();
        for (UidStatus item : items) {
            result.put(item.getEmail(), item);
        }
        return result;
    }

    private List<Long> getLongArrayAsList(long[] longList) {
        Long[] longs = new Long[longList.length];
        int i = 0;
        for (Long aLong : longList) {
            longs[i++] = aLong;
        }
        return Arrays.asList(longs);
    }
}
