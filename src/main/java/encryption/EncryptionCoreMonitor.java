package encryption;

import domain.SecureResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.text.DecimalFormat;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;

public class EncryptionCoreMonitor implements Runnable {
    Logger                     logger           = LoggerFactory.getLogger(EncryptionCoreMonitor.class);
    SecureResult[]             results          = null;
    List<Future<SecureResult>> coreList         = null;
    Set<Integer>               completedTaskIds = new HashSet<>();
    int                        doneTasks        = 0;
    int                        numTasks         = 0;

    volatile boolean done = false;

    public EncryptionCoreMonitor(SecureResult[] results, List<Future<SecureResult>> coreList) {
        this.results = results;
        this.coreList = coreList;
        numTasks = coreList.size();
    }

    @Override
    public void run() {
        Thread.currentThread().setName("encryptionCoreMonitor");
        while ((coreList.isEmpty()) || (doneTasks < coreList.size()) ) {
            for (int i = 0; i < coreList.size(); i++) {
                Future<SecureResult> resultFuture = coreList.get(i);
                if (!completedTaskIds.contains(new Integer(i)) && resultFuture.isDone()) {
                    doneTasks++;
                    completedTaskIds.add(new Integer(i));
                    try {
                        SecureResult coreResult = resultFuture.get();
                        results[coreResult.getBlockId()] = coreResult;
                        logger.info("Task num " + coreResult.getBlockId() + " done. Total progress = " + (new
                                DecimalFormat("###.##")).format((double) numTasks / (double) doneTasks * 100.0d));

                        if (doneTasks == numTasks) {
                            done = true;
                        }

                    } catch (InterruptedException e) {
                        logger.error("InterruptedException", e);
                    } catch (ExecutionException e) {
                        logger.error("ExecutionException", e);
                    }
                }
            }
        }
    }

    public boolean isDone() {
        return done;
    }
}
