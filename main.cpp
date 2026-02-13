#include <iostream>
#include <vector>
#include <string>
#include <map>
#include <fstream>
#include <sstream>
#include <stack>
#include <algorithm>
#include <cctype>
#include <filesystem>

using namespace std;

string toLower(string s) {
    for (char& c : s) c = tolower(c);
    return s;
}


// Part 1 DFA (Scanner)
// Handles Pattern Recognition (Fixed) (pattern because one letter at a time)

class OptimizedDFA {
private:
    struct State {
        int id;
        int depth;
        bool isFinal;
        string label;
        map<char, int> transitions;
    };

    vector<State> states;
    vector<string> loadedPatterns;

public:
    OptimizedDFA() {
        states.push_back({0, 0, false, "Start", {}});
    }

    // 1. Load File
    void buildFromFile(const string& filename) {
        ifstream file(filename);
        if (!file.is_open()) {
            cout << "[WARNING] Could not open " << filename << ". Using default patterns.\n";
            insertWord("union");
            insertWord("select");
            insertWord("admin");
            return;
        }

        string word;
        loadedPatterns.clear();
        while (file >> word) {
            string w = toLower(word);
            insertWord(w);
            loadedPatterns.push_back(w);
        }
        file.close();
        cout << "[System] Patterns loaded. DFA constructed.\n";
    }

    // Internal Logic 
    // Each predefined malicious word is converted into a chain of state transitions inside the DFA.
    // used to convert the word into transitions first.
    void insertWord(string word) {
        int current = 0;
        int currentDepth = 0;

        for (char c : word) {   //we loop each character of the word
            currentDepth++;
            if (states[current].transitions.find(c) == states[current].transitions.end()) { //For each character, we check if a transition already exists from the current state
                int next = states.size();
                string chunk = (current == 0) ? string(1, c) : states[current].label + c;
                states.push_back({next, currentDepth, false, chunk, {}});
                states[current].transitions[c] = next;
            }
            current = states[current].transitions[c];
        }
        states[current].isFinal = true; //After the last letter, we mark the final state as an accepting state
        states[current].label = word;
    }
   // Diagram Generator (Visual of every states) ===
    void generateDOT() {
        ofstream out("dfa_visual.dot");
        out << "digraph mDFA {\n";
        out << "  rankdir=LR;\n";
        out << "  node [shape = circle, style=filled, fillcolor=white, fontname=\"Arial\"];\n";

        // Hub
        out << "  q0 [fillcolor=lightgrey, label=\"q0\\n(START)\"];\n";

        int uniqueNodeID = 1;

        // Loop through each word to draw chains
        for (const string& word : loadedPatterns) {
            int prevID = 0;
            string currentLabel = "";

            for (int i = 0; i < word.length(); i++) {
                char c = word[i];
                currentLabel += c;
                int myID = uniqueNodeID++;

                bool isFinal = (i == word.length() - 1);
                string shape = isFinal ? "doublecircle" : "circle";
                string color = isFinal ? "lightpink" : "white";

                // Label shows Depth (q1, q2...) + Letter (u, un...)
                string visualLabel = "q" + to_string(i+1) + "\\n(" + currentLabel + ")";

                if (isFinal) visualLabel = "DETECTED:\\n" + word;

                out << "  node" << myID << " [shape=" << shape << ", fillcolor=" << color << ", label=\"" << visualLabel << "\"];\n";

                // Connect
                string source = (prevID == 0) ? "q0" : "node" + to_string(prevID);
                string target = "node" + to_string(myID);
                out << "  " << source << " -> " << target << " [label=\"" << c << "\"];\n";
                prevID = myID;
            }
        }

        // Legend Box
        out << "  subgraph cluster_legend {\n";
        out << "    label = \"Active Patterns\";\n";
        out << "    style=filled; color=lightyellow;\n";
        out << "    node [shape=box, style=filled, fillcolor=white];\n";
        string list = "";
        for(const string& p : loadedPatterns) list += p + "\\n";
        out << "    Legend [label=\"" << list << "\"];\n";
        out << "  }\n";

        out << "}\n";
        out.close();
        cout << "[System] Generated 'dfa_visual.dot' (Parallel Chains Visual).\n";
    }
 

    // SCANNER (SILENT BUFFER + STRICT CHECK)
    void scan(string text) {
        cout << "\n--- SCANNING INPUT: " << text << " ---\n";
        string input = toLower(text);
        int current = 0;
        int threatsFound = 0;

        // Stores steps Only printed if a full malicious word is found.
        vector<string> traceBuffer;

        for (int i = 0; i < input.length(); i++) { //Loop through each character in the input string  "hello union"
            char c = input[i];

            if (states[current].transitions.count(c)) { //Check if DFA has a valid transition for this character ex "h"from hello, no malicious word starts with h so proceed to else  ///#1
                int next = states[current].transitions[c]; //Move to next state based on transition

                // Record step: q0 -> q1 -> q2 ...
                string step = "  State q" + to_string(states[current].depth) +
                              " --(" + string(1, c) + ")--> q" + to_string(states[next].depth);
                traceBuffer.push_back(step);

                current = next;
            } else {    
                // MISMATCH: Clear buffer (User sees nothing for partial fails like "admins")
                traceBuffer.clear(); //discard partial match 

                // RESET LOGIC: Does this char start a NEW word? // if hello select is input, ignores hello then proceeds to FROM START below
                if (current != 0) {   // if current is not at the start state then go back to 0 /// Reset DFA back to start state

                    current = 0; 
                    if(states[0].transitions.count(c)) {  //Check if current character could start a new malicious word // If the current state has a transition for the character c,
                        int next = states[0].transitions[c];
                        string step = "  State q0 --(" + string(1, c) + ")--> q" + to_string(states[next].depth);
                        traceBuffer.push_back(step); // record transition
                        current = next; // move into new word chain
                    }
                } else if(states[0].transitions.count(c)) {  //if already in the same word, check if char begins a malicious word

                     // From start
                     int next = states[0].transitions[c];
                     string step = "  State q0 --(" + string(1, c) + ")--> q" + to_string(states[next].depth);
                     traceBuffer.push_back(step);
                     current = next;
                }
            }

            // CHECK MATCH   
            if (states[current].isFinal) {                                          ///#2
                char nextChar = (i + 1 < input.length()) ? input[i+1] : ' ';
                bool isEndOfWord = (!isalnum(nextChar)); // dapat Space, tab, or end of string,  otherwise if =isalnum or alphanumeric mugawas after word then FALSE 

                if (isEndOfWord) {
                    // SUCCESS! Print the hidden buffer now.
                    for(const string& s : traceBuffer) {
                        cout << s << endl;
                    }

                    cout << "  >>> [ALARM] MALICIOUS WORD FOUND: " << states[current].label << " <<<\n";
                    cout << "   [Scan Complete] -------------------\n";

                    threatsFound++;
                    current = 0;
                    traceBuffer.clear();
                }
            }
        }

        cout << "\n=========================================\n";
        if (threatsFound == 0) cout << "  >>> Result: Clean Traffic.\n";
        else cout << "  >>> Result: " << threatsFound << " threats detected!\n";
    }
};


// PART 2: Pushdown Automata (PDA)
// TCP handshake is used to make sure the connection is considered established
// A PDA has a stack memory, which allows it to track nested or ordered sequences(Handshake requires order validation)

class HandshakePDA {
private:
    stack<string> stackStorage;

public:
    void generateDOT() {
        ofstream out("pda_visual.dot");
        out << "digraph PDA {\n rankdir=TB;\n node [shape=record];\n";
        out << "  State0 [label=\"{State: LISTEN | Stack: Empty}\"];\n";
        out << "  State1 [label=\"{State: SYN_RCVD | Stack: A}\"];\n";
        out << "  State2 [label=\"{State: ESTABLISHED | Stack: Empty}\", style=filled, fillcolor=lightgreen];\n";
        out << "  State0 -> State1 [label=\"In: SYN\\nPush: A\"];\n";
        out << "  State1 -> State1 [label=\"In: SYN-ACK\\nPop: A, Push: B\"];\n";
        out << "  State1 -> State2 [label=\"In: ACK\\nPop: B\"];\n}\n";
        out.close();
        cout << "[System] Generated 'pda_visual.dot'.\n";
    }

    void simulate(vector<string> inputs) {
        while(!stackStorage.empty()) stackStorage.pop(); //This clears the stack before starting.
        stackStorage.push("ACK"); stackStorage.push("SYN-ACK"); stackStorage.push("SYN"); //the push expected order
        cout << "\n--- PDA SIMULATION ---\n";
        for (string s : inputs) { //It reads each input
            if (stackStorage.empty()) { cout << "  Error: Stack empty!\n"; return; }
            string expected = stackStorage.top(); //Compare With Top of Stack which is SYN
            for(auto &c : s) c = toupper(c);      //checks whether user types smaller case then converts it to uppercase
            cout << "  Input: " << s << " | Expected: " << expected;
            if (s == expected) { stackStorage.pop(); cout << " -> MATCH.\n"; }
            else { cout << " -> MISMATCH.\n"; return; }
        }
        if (stackStorage.empty()) cout << ">>> HANDSHAKE SUCCESSFUL <<<\n";
        else cout << ">>> INCOMPLETE <<<\n";
    }
};

// MAIN CONTROLLER
int main() {
    OptimizedDFA dfa;
    HandshakePDA pda;

    cout << "=========================================\n";
    cout << "   SIMPLE CHOMSKY HIERARCHY MALICIOUS WORD SCANNER AND PDA VALIDATION     \n";
    cout << "=========================================\n";
    cout << "[DEBUG] Looking for patterns.txt in:\n        " << filesystem::current_path() << "\n\n";

    dfa.buildFromFile("patterns.txt");
    dfa.generateDOT();
    pda.generateDOT();
    cout << "-----------------------------------------\n";

    while (true) {
        cout << "\nMENU:\n1. Test DFA Malicious Word/s Scanner\n2. PDA Validation TCP Handshake\n0. Exit\nChoice: ";
        int choice; cin >> choice; cin.ignore();
        if (choice == 0) break;
        if (choice == 1) {
            string line; cout << "Enter text: "; getline(cin, line);
            dfa.scan(line);
        }
        else if (choice == 2) {
            string line; cout << "Enter sequence: "; getline(cin, line);
            stringstream ss(line); string s; vector<string> v;
            while(ss >> s) v.push_back(s); pda.simulate(v);
        }
    }
    return 0;
}