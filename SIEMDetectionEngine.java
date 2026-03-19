import java.time.*;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.regex.*;

/**
 * SIEM-style Simple Detection Engine (Java)
 */
public class SIEMDetectionEngine {

    /* ---------------- CONFIGURATION ---------------- */
    static final int IP_FAILURE_THRESHOLD = 5;
    static final Duration IP_WINDOW = Duration.ofSeconds(60);

    static final int USER_FAILURE_THRESHOLD = 5;
    static final Duration USER_WINDOW = Duration.ofMinutes(5);

    static final int SPRAY_USER_UNIQUE = 5;
    static final Duration SPRAY_WINDOW = Duration.ofHours(1);

    static final int FOLLOWUP_FAILURES = 4;
    static final Duration FOLLOWUP_WINDOW = Duration.ofMinutes(15);

    /* ---------------- REGEX ---------------- */
    static final Pattern RE_IP = Pattern.compile("(\\d{1,3}(?:\\.\\d{1,3}){3})");
    static final Pattern RE_USER = Pattern.compile(
            "(?:user(?:name)?=|invalid user |for user )([\\w@.\\-]+)",
            Pattern.CASE_INSENSITIVE
    );
    static final Pattern RE_FAIL = Pattern.compile(
            "(failed|failure|invalid user|password mismatch)",
            Pattern.CASE_INSENSITIVE
    );
    static final Pattern RE_SUCCESS = Pattern.compile(
            "(success|accepted|logged in|session opened)",
            Pattern.CASE_INSENSITIVE
    );

    /* ---------------- EVENT MODEL ---------------- */
    static class Event {
        LocalDateTime ts;
        String ip;
        String user;
        String outcome;
        String raw;

        Event(LocalDateTime ts, String ip, String user, String outcome, String raw) {
            this.ts = ts;
            this.ip = ip;
            this.user = user;
            this.outcome = outcome;
            this.raw = raw;
        }
    }

    /* ---------------- DETECTOR ---------------- */
    static class Detector {

        Map<String, Deque<LocalDateTime>> ipFails = new HashMap<>();
        Map<String, Deque<LocalDateTime>> userFails = new HashMap<>();
        Map<String, Deque<Pair>> ipUserAttempts = new HashMap<>();
        Map<String, Deque<LocalDateTime>> recentFailHistory = new HashMap<>();

        List<Map<String, String>> findings = new ArrayList<>();

        void ingest(Event e) {
            if (e.outcome.equals("UNKNOWN")) return;

            if (e.outcome.equals("FAIL")) {
                trackIpBruteForce(e);
                trackUserBruteForce(e);
                trackPasswordSpray(e);
                trackRecentFailures(e);
            } else if (e.outcome.equals("SUCCESS")) {
                detectSuccessAfterFails(e);
            }
        }

        void trackIpBruteForce(Event e) {
            Deque<LocalDateTime> dq = ipFails.computeIfAbsent(e.ip, k -> new ArrayDeque<>());
            dq.add(e.ts);
            prune(dq, e.ts, IP_WINDOW);

            if (dq.size() >= IP_FAILURE_THRESHOLD) {
                raise("IP_BRUTE_FORCE", e, dq.size() + " failures from IP within 60s");
            }
        }

        void trackUserBruteForce(Event e) {
            Deque<LocalDateTime> dq = userFails.computeIfAbsent(e.user, k -> new ArrayDeque<>());
            dq.add(e.ts);
            prune(dq, e.ts, USER_WINDOW);

            if (dq.size() >= USER_FAILURE_THRESHOLD) {
                raise("ACCOUNT_BRUTE_FORCE", e, dq.size() + " failures for user within 5 min");
            }
        }

        void trackPasswordSpray(Event e) {
            Deque<Pair> dq = ipUserAttempts.computeIfAbsent(e.ip, k -> new ArrayDeque<>());
            dq.add(new Pair(e.ts, e.user));
            prunePairs(dq, e.ts, SPRAY_WINDOW);

            Set<String> users = new HashSet<>();
            for (Pair p : dq) users.add(p.user);

            if (users.size() >= SPRAY_USER_UNIQUE) {
                raise("PASSWORD_SPRAY", e, users.size() + " distinct users tried");
            }
        }

        void trackRecentFailures(Event e) {
            String key = e.user + "|" + e.ip;
            Deque<LocalDateTime> dq = recentFailHistory.computeIfAbsent(key, k -> new ArrayDeque<>());
            dq.add(e.ts);
            prune(dq, e.ts, FOLLOWUP_WINDOW);
        }

        void detectSuccessAfterFails(Event e) {
            String key = e.user + "|" + e.ip;
            Deque<LocalDateTime> dq = recentFailHistory.getOrDefault(key, new ArrayDeque<>());
            prune(dq, e.ts, FOLLOWUP_WINDOW);

            if (dq.size() >= FOLLOWUP_FAILURES) {
                raise("SUCCESS_AFTER_FAILS", e,
                        "Successful login after " + dq.size() + " failures");
            }
            recentFailHistory.remove(key);
        }

        void prune(Deque<LocalDateTime> dq, LocalDateTime now, Duration window) {
            while (!dq.isEmpty() && Duration.between(dq.peekFirst(), now).compareTo(window) > 0) {
                dq.pollFirst();
            }
        }

        void prunePairs(Deque<Pair> dq, LocalDateTime now, Duration window) {
            while (!dq.isEmpty() &&
                    Duration.between(dq.peekFirst().ts, now).compareTo(window) > 0) {
                dq.pollFirst();
            }
        }

        void raise(String type, Event e, String evidence) {
            Map<String, String> f = new LinkedHashMap<>();
            f.put("type", type);
            f.put("time", e.ts.toString());
            f.put("src_ip", e.ip);
            f.put("user", e.user);
            f.put("evidence", evidence);

            if (!findings.contains(f)) findings.add(f);
        }

        void printSummary() {
            System.out.println("{ \"findings\": [");
            for (int i = 0; i < findings.size(); i++) {
                System.out.println("  " + findings.get(i));
                if (i < findings.size() - 1) System.out.println(",");
            }
            System.out.println("]}");
        }
    }

    static class Pair {
        LocalDateTime ts;
        String user;

        Pair(LocalDateTime ts, String user) {
            this.ts = ts;
            this.user = user;
        }
    }

    /* ---------------- PARSER ---------------- */
    static Event parse(String line) {
        LocalDateTime ts = LocalDateTime.now();

        Matcher ipM = RE_IP.matcher(line);
        String ip = ipM.find() ? ipM.group() : "unknown";

        Matcher userM = RE_USER.matcher(line);
        String user = userM.find() ? userM.group(1) : "unknown";

        String outcome = "UNKNOWN";
        if (RE_FAIL.matcher(line).find()) outcome = "FAIL";
        else if (RE_SUCCESS.matcher(line).find()) outcome = "SUCCESS";
        else if (line.contains(" 200 ")) outcome = "SUCCESS";
        else if (line.contains(" 401 ") || line.contains(" 403 ")) outcome = "FAIL";

        return new Event(ts, ip, user, outcome, line);
    }

    /* ---------------- MAIN ---------------- */
    public static void main(String[] args) {
        Detector detector = new Detector();

        List<String> logs = Arrays.asList(
                "Failed password for root from 10.0.0.5",
                "Failed password for admin from 10.0.0.5",
                "Failed password for test from 10.0.0.5",
                "Failed password for guest from 10.0.0.5",
                "Failed password for oracle from 10.0.0.5",
                "Accepted password for admin from 10.0.0.5"
        );

        for (String line : logs) {
            detector.ingest(parse(line));
        }

        detector.printSummary();
    }
}
