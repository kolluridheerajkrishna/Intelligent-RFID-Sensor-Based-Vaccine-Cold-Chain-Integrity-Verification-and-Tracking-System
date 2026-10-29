// VACCINE COLD-CHAIN MONITOR (within 200 lines, built-in input)
// Queue | Linked list | Max-heap | Graph | unordered_map
// Rule: exposure += (degrees outside 2-8 C) x minutes between readings; exposure > limit -> COMPROMISED
// Build: g++ -std=c++17 -Wall -Wextra -o coldchain coldchain_200.cpp      Run: ./coldchain
#include <algorithm>
#include <iomanip>
#include <iostream>
#include <queue>
#include <string>
#include <unordered_map>
#include <vector>
using namespace std;

// ===== 1. SETTINGS =====
const double SAFE_MIN = 2.0, SAFE_MAX = 8.0;   // safe range (C)
const double LIMIT = 120.0;                    // allowed degree-minutes
struct Reading { string id; int ts; double temp; string centre; };
double deviation(double t) {                   // degrees outside the safe range
    return t < SAFE_MIN ? SAFE_MIN - t : (t > SAFE_MAX ? t - SAFE_MAX : 0.0);
}

// ===== 2. GIVEN INPUT {container, minute, temp C, centre} =====
vector<Reading> givenInput() {
    return {   // VX-1001 stays safe | VX-1002 cooling failure | VX-1003 near limit, safe | VX-1004 skipped a depot
        {"VX-1001", 0, 5.0, "Central Store"},      {"VX-1001", 30, 5.5, "Central Store"},
        {"VX-1001", 60, 6.0, "Regional Depot A"},  {"VX-1001", 90, 5.8, "Regional Depot A"},
        {"VX-1001", 120, 6.2, "City Hospital"},    {"VX-1002", 0, 5.0, "Central Store"},
        {"VX-1002", 30, 5.0, "Central Store"},     {"VX-1002", 60, 11.0, "Regional Depot A"},
        {"VX-1002", 90, 12.0, "Regional Depot A"}, {"VX-1002", 120, 6.0, "City Hospital"},
        {"VX-1003", 0, 5.0, "Central Store"},      {"VX-1003", 30, 9.0, "Central Store"},
        {"VX-1003", 60, 10.0, "Regional Depot B"}, {"VX-1003", 90, 8.5, "Regional Depot B"},
        {"VX-1003", 120, 5.0, "District Hospital"},{"VX-1004", 0, 4.0, "Central Store"},
        {"VX-1004", 45, 4.5, "Central Store"},     {"VX-1004", 90, 5.0, "City Hospital"},
    };
}

// ===== 3. QUEUE (linked FIFO): readings processed in arrival order =====
class ReadingQueue {
    struct Node { Reading r; Node* next; };
    Node *head = nullptr, *tail = nullptr;
public:
    ReadingQueue() = default;  ReadingQueue(const ReadingQueue&) = delete;  ReadingQueue& operator=(const ReadingQueue&) = delete;
    ~ReadingQueue() { while (!empty()) pop(); }
    bool empty() const { return head == nullptr; }
    void push(const Reading& r) {                  // add at back
        Node* n = new Node{r, nullptr};
        (tail ? tail->next : head) = n;  tail = n;
    }
    Reading pop() {                                // remove from front
        Node* n = head;  Reading r = n->r;
        head = n->next;  if (!head) tail = nullptr;
        delete n;  return r;
    }
};

// ===== 4. LINKED LIST: one node per storage centre visited =====
class RouteList {
public:
    struct Node { string centre; double worst; Node* next; };
    Node *head = nullptr, *tail = nullptr;
    RouteList() = default;  RouteList(const RouteList&) = delete;  RouteList& operator=(const RouteList&) = delete;
    ~RouteList() { while (head) { Node* n = head; head = head->next; delete n; } }
    void record(const string& centre, double temp) {
        if (tail && tail->centre == centre) {      // same centre: keep worst temp
            if (deviation(temp) > deviation(tail->worst)) tail->worst = temp;
            return;
        }
        Node* n = new Node{centre, temp, nullptr}; // new centre: add node
        (tail ? tail->next : head) = n;  tail = n;
    }
};

// ===== 5. CONTAINER: exposure + status of one vaccine box =====
struct Container {
    string id;  double exposure = 0, limit;
    bool compromised = false, hasLast = false;
    int flaggedAt = -1, lastTs = 0;
    RouteList route;
    Container(string i, double l) : id(move(i)), limit(l) {}
    bool addReading(const Reading& r) {            // true when newly compromised
        route.record(r.centre, r.temp);
        if (hasLast && r.ts > lastTs) exposure += deviation(r.temp) * (r.ts - lastTs);
        hasLast = true;  lastTs = r.ts;
        if (!compromised && exposure > limit) { compromised = true;  flaggedAt = r.ts;  return true; }
        return false;
    }
    double risk() const { return exposure / limit; }   // 1.0 = at limit
};

// ===== 6. MAX-HEAP: most at-risk container at the top =====
class RiskHeap {
    vector<pair<double, string>> a;
public:
    bool empty() const { return a.empty(); }
    void push(double ratio, const string& id) {    // add, bubble up
        a.emplace_back(ratio, id);
        for (size_t i = a.size() - 1; i > 0 && a[(i - 1) / 2].first < a[i].first; i = (i - 1) / 2)
            swap(a[i], a[(i - 1) / 2]);
    }
    pair<double, string> pop() {                   // take top, sift down
        pair<double, string> top = a.front();
        a.front() = a.back();  a.pop_back();
        size_t i = 0;
        for (;;) {
            size_t l = 2 * i + 1, r = l + 1, m = i;
            if (l < a.size() && a[l].first > a[m].first) m = l;
            if (r < a.size() && a[r].first > a[m].first) m = r;
            if (m == i) break;
            swap(a[i], a[m]);  i = m;
        }
        return top;
    }
};

// ===== 7. GRAPH: storage-centre network (adjacency list) =====
class CentreGraph {
    unordered_map<string, vector<string>> adj;
public:
    void addEdge(const string& u, const string& v) { adj[u].push_back(v); adj[v].push_back(u); }
    bool connected(const string& u, const string& v) const {
        auto it = adj.find(u);
        return it != adj.end() && find(it->second.begin(), it->second.end(), v) != it->second.end();
    }
    vector<string> shortestPath(const string& s, const string& d) const {   // BFS
        if (!adj.count(s) || !adj.count(d)) return {};
        unordered_map<string, string> parent;
        parent[s] = s;                                // parent also marks visited nodes
        queue<string> q;  q.push(s);
        while (!q.empty() && !parent.count(d)) {
            string u = q.front(); q.pop();
            for (const string& v : adj.at(u))
                if (parent.emplace(v, u).second) q.push(v);
        }
        if (!parent.count(d)) return {};
        vector<string> path{d};
        while (path.back() != s) path.push_back(parent[path.back()]);
        reverse(path.begin(), path.end());  return path;
    }
};

// ===== 8. MAIN =====
int main() {
    // Step 1: build the centre network
    CentreGraph net;
    const char* links[][2] = {{"Central Store", "Regional Depot A"}, {"Central Store", "Regional Depot B"},
        {"Regional Depot A", "Regional Depot B"}, {"Regional Depot A", "City Hospital"}, {"Regional Depot B", "District Hospital"}};
    for (auto& l : links) net.addEdge(l[0], l[1]);
    // Step 2: sort readings by time, load into the queue
    vector<Reading> readings = givenInput();
    stable_sort(readings.begin(), readings.end(), [](const Reading& a, const Reading& b) { return a.ts < b.ts; });
    ReadingQueue feed;
    for (const Reading& r : readings) feed.push(r);
    // Step 3: process the queue, raise alerts
    unordered_map<string, Container> boxes;   // id -> container
    vector<string> order;                                 // first-seen order
    cout << fixed << setprecision(1) << "=== Monitoring (limit " << LIMIT
         << " degree-minutes, safe " << SAFE_MIN << "-" << SAFE_MAX << "C) ===\n";
    while (!feed.empty()) {
        Reading r = feed.pop();
        auto it = boxes.find(r.id);
        if (it == boxes.end()) { it = boxes.try_emplace(r.id, r.id, LIMIT).first;  order.push_back(r.id); }
        Container& c = it->second;
        if (c.addReading(r))
            cout << "[ALERT] t=" << r.ts << " " << c.id << " COMPROMISED at " << r.centre
                 << " (exposure " << c.exposure << " > " << c.limit << ")\n";
    }
    // Step 4: risk ranking (max-heap)
    RiskHeap heap;
    for (const string& id : order) heap.push(boxes.at(id).risk(), id);
    cout << "\n--- Risk ranking (closest to limit first) ---\n";
    for (int k = 1; !heap.empty(); ++k) {
        auto t = heap.pop();
        cout << "  " << k << ". " << t.second << "  " << setprecision(0) << t.first * 100 << "% of limit\n" << setprecision(1);
    }
    // Step 5: routes + skipped-link check (linked list + graph)
    cout << "\n--- Routes (worst temperature per centre) ---\n";
    for (const string& id : order) {
        string anomalies;  cout << "  " << id << ": ";
        for (auto* n = boxes.at(id).route.head; n; n = n->next) {
            cout << n->centre << " [" << n->worst << "C]" << (n->next ? " -> " : "\n");
            if (n->next && !net.connected(n->centre, n->next->centre)) {
                auto p = net.shortestPath(n->centre, n->next->centre);
                anomalies += "      ! no direct link " + n->centre + " -> " + n->next->centre;
                if (p.size() > 2) anomalies += " (expected via " + p[1] + ")";
                anomalies += "\n";
            }
        }
        cout << anomalies;
    }
    // Step 6: final report
    cout << "\n=== FINAL REPORT ===\n" << left << setw(10) << "Container" << right
         << setw(10) << "Exposure" << setw(8) << "Limit" << "   Status\n";
    int bad = 0;
    for (const string& id : order) {
        const Container& c = boxes.at(id);
        cout << left << setw(10) << c.id << right << setw(10) << c.exposure << setw(8) << c.limit << "   ";
        if (c.compromised) { cout << "COMPROMISED (t=" << c.flaggedAt << ")\n"; ++bad; }
        else cout << "SAFE\n";
    }
    cout << "\nSafe: " << order.size() - bad << "   Compromised: " << bad << "\n";
}
