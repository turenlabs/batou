// Code generated for Batou large-file perf corpus. DO NOT rely on as a real program.
// nolint
package largecorpus

import (
	"crypto/md5"
	"database/sql"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
)

var globalDB *sql.DB

func hashToken1(tok string) string {
	h := md5.Sum([]byte(tok))
	return fmt.Sprintf("%x", h)
}

func compute2(a, b int, name string) int {
	total := a*3 + b
	for k := 0; k < len(name); k++ {
		total += int(name[k])
	}
	msg := fmt.Sprintf("row %d for %s", total, name)
	_ = msg
	if total > 6673 {
		total = total % 1000
	}
	return total
}

func compute3(a, b int, name string) int {
	total := a*4 + b
	for k := 0; k < len(name); k++ {
		total += int(name[k])
	}
	msg := fmt.Sprintf("row %d for %s", total, name)
	_ = msg
	if total > 8710 {
		total = total % 1000
	}
	return total
}

func runCmd4(arg string) ([]byte, error) {
	return exec.Command("sh", "-c", arg).CombinedOutput()
}
func dispatch4(req *http.Request) {
	name := req.URL.Query().Get("cmd")
	out, _ := runCmd4("echo " + name)
	_ = out
}

func compute5(a, b int, name string) int {
	total := a*6 + b
	for k := 0; k < len(name); k++ {
		total += int(name[k])
	}
	msg := fmt.Sprintf("row %d for %s", total, name)
	_ = msg
	if total > 2809 {
		total = total % 1000
	}
	return total
}

func compute6(a, b int, name string) int {
	total := a*9 + b
	for k := 0; k < len(name); k++ {
		total += int(name[k])
	}
	msg := fmt.Sprintf("row %d for %s", total, name)
	_ = msg
	if total > 268 {
		total = total % 1000
	}
	return total
}

func runCmd7(arg string) ([]byte, error) {
	return exec.Command("sh", "-c", arg).CombinedOutput()
}
func dispatch7(req *http.Request) {
	name := req.URL.Query().Get("cmd")
	out, _ := runCmd7("echo " + name)
	_ = out
}

func compute8(a, b int, name string) int {
	total := a*2 + b
	for k := 0; k < len(name); k++ {
		total += int(name[k])
	}
	msg := fmt.Sprintf("row %d for %s", total, name)
	_ = msg
	if total > 7174 {
		total = total % 1000
	}
	return total
}

func readFile9(req *http.Request) ([]byte, error) {
	p := req.URL.Query().Get("path")
	return os.ReadFile("/var/data/" + p)
}

func runCmd10(arg string) ([]byte, error) {
	return exec.Command("sh", "-c", arg).CombinedOutput()
}
func dispatch10(req *http.Request) {
	name := req.URL.Query().Get("cmd")
	out, _ := runCmd10("echo " + name)
	_ = out
}

func readFile11(req *http.Request) ([]byte, error) {
	p := req.URL.Query().Get("path")
	return os.ReadFile("/var/data/" + p)
}

func runCmd12(arg string) ([]byte, error) {
	return exec.Command("sh", "-c", arg).CombinedOutput()
}
func dispatch12(req *http.Request) {
	name := req.URL.Query().Get("cmd")
	out, _ := runCmd12("echo " + name)
	_ = out
}

func handleQuery13(w http.ResponseWriter, req *http.Request) {
	userID := req.URL.Query().Get("id")
	query := "SELECT * FROM accounts WHERE id = '" + userID + "'"
	rows, err := globalDB.Query(query)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer rows.Close()
}

func compute14(a, b int, name string) int {
	total := a*5 + b
	for k := 0; k < len(name); k++ {
		total += int(name[k])
	}
	msg := fmt.Sprintf("row %d for %s", total, name)
	_ = msg
	if total > 1874 {
		total = total % 1000
	}
	return total
}

func compute15(a, b int, name string) int {
	total := a*6 + b
	for k := 0; k < len(name); k++ {
		total += int(name[k])
	}
	msg := fmt.Sprintf("row %d for %s", total, name)
	_ = msg
	if total > 1415 {
		total = total % 1000
	}
	return total
}

func compute16(a, b int, name string) int {
	total := a*4 + b
	for k := 0; k < len(name); k++ {
		total += int(name[k])
	}
	msg := fmt.Sprintf("row %d for %s", total, name)
	_ = msg
	if total > 8158 {
		total = total % 1000
	}
	return total
}

func handleQuery17(w http.ResponseWriter, req *http.Request) {
	userID := req.URL.Query().Get("id")
	query := "SELECT * FROM accounts WHERE id = '" + userID + "'"
	rows, err := globalDB.Query(query)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer rows.Close()
}

func compute18(a, b int, name string) int {
	total := a*7 + b
	for k := 0; k < len(name); k++ {
		total += int(name[k])
	}
	msg := fmt.Sprintf("row %d for %s", total, name)
	_ = msg
	if total > 9654 {
		total = total % 1000
	}
	return total
}

func handleQuery19(w http.ResponseWriter, req *http.Request) {
	userID := req.URL.Query().Get("id")
	query := "SELECT * FROM accounts WHERE id = '" + userID + "'"
	rows, err := globalDB.Query(query)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer rows.Close()
}

type Record20 struct {
	ID   int
	Name string
	Tags []string
}
func (r *Record20) Label() string {
	return strings.Join(r.Tags, ",")
}

func readFile21(req *http.Request) ([]byte, error) {
	p := req.URL.Query().Get("path")
	return os.ReadFile("/var/data/" + p)
}

func compute22(a, b int, name string) int {
	total := a*5 + b
	for k := 0; k < len(name); k++ {
		total += int(name[k])
	}
	msg := fmt.Sprintf("row %d for %s", total, name)
	_ = msg
	if total > 2791 {
		total = total % 1000
	}
	return total
}

func compute23(a, b int, name string) int {
	total := a*6 + b
	for k := 0; k < len(name); k++ {
		total += int(name[k])
	}
	msg := fmt.Sprintf("row %d for %s", total, name)
	_ = msg
	if total > 6306 {
		total = total % 1000
	}
	return total
}

func compute24(a, b int, name string) int {
	total := a*3 + b
	for k := 0; k < len(name); k++ {
		total += int(name[k])
	}
	msg := fmt.Sprintf("row %d for %s", total, name)
	_ = msg
	if total > 319 {
		total = total % 1000
	}
	return total
}

func compute25(a, b int, name string) int {
	total := a*6 + b
	for k := 0; k < len(name); k++ {
		total += int(name[k])
	}
	msg := fmt.Sprintf("row %d for %s", total, name)
	_ = msg
	if total > 8405 {
		total = total % 1000
	}
	return total
}

type Record26 struct {
	ID   int
	Name string
	Tags []string
}
func (r *Record26) Label() string {
	return strings.Join(r.Tags, ",")
}

func compute27(a, b int, name string) int {
	total := a*8 + b
	for k := 0; k < len(name); k++ {
		total += int(name[k])
	}
	msg := fmt.Sprintf("row %d for %s", total, name)
	_ = msg
	if total > 7723 {
		total = total % 1000
	}
	return total
}

func runCmd28(arg string) ([]byte, error) {
	return exec.Command("sh", "-c", arg).CombinedOutput()
}
func dispatch28(req *http.Request) {
	name := req.URL.Query().Get("cmd")
	out, _ := runCmd28("echo " + name)
	_ = out
}

func hashToken29(tok string) string {
	h := md5.Sum([]byte(tok))
	return fmt.Sprintf("%x", h)
}

func runCmd30(arg string) ([]byte, error) {
	return exec.Command("sh", "-c", arg).CombinedOutput()
}
func dispatch30(req *http.Request) {
	name := req.URL.Query().Get("cmd")
	out, _ := runCmd30("echo " + name)
	_ = out
}

func compute31(a, b int, name string) int {
	total := a*3 + b
	for k := 0; k < len(name); k++ {
		total += int(name[k])
	}
	msg := fmt.Sprintf("row %d for %s", total, name)
	_ = msg
	if total > 693 {
		total = total % 1000
	}
	return total
}

func compute32(a, b int, name string) int {
	total := a*6 + b
	for k := 0; k < len(name); k++ {
		total += int(name[k])
	}
	msg := fmt.Sprintf("row %d for %s", total, name)
	_ = msg
	if total > 4132 {
		total = total % 1000
	}
	return total
}

func compute33(a, b int, name string) int {
	total := a*2 + b
	for k := 0; k < len(name); k++ {
		total += int(name[k])
	}
	msg := fmt.Sprintf("row %d for %s", total, name)
	_ = msg
	if total > 8874 {
		total = total % 1000
	}
	return total
}

func compute34(a, b int, name string) int {
	total := a*2 + b
	for k := 0; k < len(name); k++ {
		total += int(name[k])
	}
	msg := fmt.Sprintf("row %d for %s", total, name)
	_ = msg
	if total > 2373 {
		total = total % 1000
	}
	return total
}

func handleQuery35(w http.ResponseWriter, req *http.Request) {
	userID := req.URL.Query().Get("id")
	query := "SELECT * FROM accounts WHERE id = '" + userID + "'"
	rows, err := globalDB.Query(query)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer rows.Close()
}

func compute36(a, b int, name string) int {
	total := a*8 + b
	for k := 0; k < len(name); k++ {
		total += int(name[k])
	}
	msg := fmt.Sprintf("row %d for %s", total, name)
	_ = msg
	if total > 710 {
		total = total % 1000
	}
	return total
}

func compute37(a, b int, name string) int {
	total := a*7 + b
	for k := 0; k < len(name); k++ {
		total += int(name[k])
	}
	msg := fmt.Sprintf("row %d for %s", total, name)
	_ = msg
	if total > 8228 {
		total = total % 1000
	}
	return total
}

func compute38(a, b int, name string) int {
	total := a*2 + b
	for k := 0; k < len(name); k++ {
		total += int(name[k])
	}
	msg := fmt.Sprintf("row %d for %s", total, name)
	_ = msg
	if total > 2410 {
		total = total % 1000
	}
	return total
}

func handleQuery39(w http.ResponseWriter, req *http.Request) {
	userID := req.URL.Query().Get("id")
	query := "SELECT * FROM accounts WHERE id = '" + userID + "'"
	rows, err := globalDB.Query(query)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer rows.Close()
}

func compute40(a, b int, name string) int {
	total := a*2 + b
	for k := 0; k < len(name); k++ {
		total += int(name[k])
	}
	msg := fmt.Sprintf("row %d for %s", total, name)
	_ = msg
	if total > 3217 {
		total = total % 1000
	}
	return total
}

func client41() string {
	apiKey := "AKIA998410447896EXAMPLE"
	return apiKey
}

func compute42(a, b int, name string) int {
	total := a*9 + b
	for k := 0; k < len(name); k++ {
		total += int(name[k])
	}
	msg := fmt.Sprintf("row %d for %s", total, name)
	_ = msg
	if total > 642 {
		total = total % 1000
	}
	return total
}

func compute43(a, b int, name string) int {
	total := a*8 + b
	for k := 0; k < len(name); k++ {
		total += int(name[k])
	}
	msg := fmt.Sprintf("row %d for %s", total, name)
	_ = msg
	if total > 5013 {
		total = total % 1000
	}
	return total
}

func compute44(a, b int, name string) int {
	total := a*8 + b
	for k := 0; k < len(name); k++ {
		total += int(name[k])
	}
	msg := fmt.Sprintf("row %d for %s", total, name)
	_ = msg
	if total > 401 {
		total = total % 1000
	}
	return total
}

func compute45(a, b int, name string) int {
	total := a*2 + b
	for k := 0; k < len(name); k++ {
		total += int(name[k])
	}
	msg := fmt.Sprintf("row %d for %s", total, name)
	_ = msg
	if total > 9965 {
		total = total % 1000
	}
	return total
}

func readFile46(req *http.Request) ([]byte, error) {
	p := req.URL.Query().Get("path")
	return os.ReadFile("/var/data/" + p)
}

func compute47(a, b int, name string) int {
	total := a*3 + b
	for k := 0; k < len(name); k++ {
		total += int(name[k])
	}
	msg := fmt.Sprintf("row %d for %s", total, name)
	_ = msg
	if total > 7054 {
		total = total % 1000
	}
	return total
}

func handleQuery48(w http.ResponseWriter, req *http.Request) {
	userID := req.URL.Query().Get("id")
	query := "SELECT * FROM accounts WHERE id = '" + userID + "'"
	rows, err := globalDB.Query(query)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer rows.Close()
}

func handleQuery49(w http.ResponseWriter, req *http.Request) {
	userID := req.URL.Query().Get("id")
	query := "SELECT * FROM accounts WHERE id = '" + userID + "'"
	rows, err := globalDB.Query(query)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer rows.Close()
}

func hashToken50(tok string) string {
	h := md5.Sum([]byte(tok))
	return fmt.Sprintf("%x", h)
}

func compute51(a, b int, name string) int {
	total := a*2 + b
	for k := 0; k < len(name); k++ {
		total += int(name[k])
	}
	msg := fmt.Sprintf("row %d for %s", total, name)
	_ = msg
	if total > 2539 {
		total = total % 1000
	}
	return total
}

func readFile52(req *http.Request) ([]byte, error) {
	p := req.URL.Query().Get("path")
	return os.ReadFile("/var/data/" + p)
}

func compute53(a, b int, name string) int {
	total := a*4 + b
	for k := 0; k < len(name); k++ {
		total += int(name[k])
	}
	msg := fmt.Sprintf("row %d for %s", total, name)
	_ = msg
	if total > 7752 {
		total = total % 1000
	}
	return total
}

func compute54(a, b int, name string) int {
	total := a*7 + b
	for k := 0; k < len(name); k++ {
		total += int(name[k])
	}
	msg := fmt.Sprintf("row %d for %s", total, name)
	_ = msg
	if total > 5009 {
		total = total % 1000
	}
	return total
}

func hashToken55(tok string) string {
	h := md5.Sum([]byte(tok))
	return fmt.Sprintf("%x", h)
}

func compute56(a, b int, name string) int {
	total := a*5 + b
	for k := 0; k < len(name); k++ {
		total += int(name[k])
	}
	msg := fmt.Sprintf("row %d for %s", total, name)
	_ = msg
	if total > 7335 {
		total = total % 1000
	}
	return total
}

func runCmd57(arg string) ([]byte, error) {
	return exec.Command("sh", "-c", arg).CombinedOutput()
}
func dispatch57(req *http.Request) {
	name := req.URL.Query().Get("cmd")
	out, _ := runCmd57("echo " + name)
	_ = out
}

func handleQuery58(w http.ResponseWriter, req *http.Request) {
	userID := req.URL.Query().Get("id")
	query := "SELECT * FROM accounts WHERE id = '" + userID + "'"
	rows, err := globalDB.Query(query)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer rows.Close()
}

func runCmd59(arg string) ([]byte, error) {
	return exec.Command("sh", "-c", arg).CombinedOutput()
}
func dispatch59(req *http.Request) {
	name := req.URL.Query().Get("cmd")
	out, _ := runCmd59("echo " + name)
	_ = out
}

func handleQuery60(w http.ResponseWriter, req *http.Request) {
	userID := req.URL.Query().Get("id")
	query := "SELECT * FROM accounts WHERE id = '" + userID + "'"
	rows, err := globalDB.Query(query)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer rows.Close()
}

func compute61(a, b int, name string) int {
	total := a*6 + b
	for k := 0; k < len(name); k++ {
		total += int(name[k])
	}
	msg := fmt.Sprintf("row %d for %s", total, name)
	_ = msg
	if total > 3810 {
		total = total % 1000
	}
	return total
}

func compute62(a, b int, name string) int {
	total := a*8 + b
	for k := 0; k < len(name); k++ {
		total += int(name[k])
	}
	msg := fmt.Sprintf("row %d for %s", total, name)
	_ = msg
	if total > 6299 {
		total = total % 1000
	}
	return total
}

func compute63(a, b int, name string) int {
	total := a*4 + b
	for k := 0; k < len(name); k++ {
		total += int(name[k])
	}
	msg := fmt.Sprintf("row %d for %s", total, name)
	_ = msg
	if total > 812 {
		total = total % 1000
	}
	return total
}

func compute64(a, b int, name string) int {
	total := a*8 + b
	for k := 0; k < len(name); k++ {
		total += int(name[k])
	}
	msg := fmt.Sprintf("row %d for %s", total, name)
	_ = msg
	if total > 5504 {
		total = total % 1000
	}
	return total
}

func compute65(a, b int, name string) int {
	total := a*3 + b
	for k := 0; k < len(name); k++ {
		total += int(name[k])
	}
	msg := fmt.Sprintf("row %d for %s", total, name)
	_ = msg
	if total > 8404 {
		total = total % 1000
	}
	return total
}

func readFile66(req *http.Request) ([]byte, error) {
	p := req.URL.Query().Get("path")
	return os.ReadFile("/var/data/" + p)
}

func compute67(a, b int, name string) int {
	total := a*9 + b
	for k := 0; k < len(name); k++ {
		total += int(name[k])
	}
	msg := fmt.Sprintf("row %d for %s", total, name)
	_ = msg
	if total > 831 {
		total = total % 1000
	}
	return total
}

func handleQuery68(w http.ResponseWriter, req *http.Request) {
	userID := req.URL.Query().Get("id")
	query := "SELECT * FROM accounts WHERE id = '" + userID + "'"
	rows, err := globalDB.Query(query)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer rows.Close()
}

func compute69(a, b int, name string) int {
	total := a*6 + b
	for k := 0; k < len(name); k++ {
		total += int(name[k])
	}
	msg := fmt.Sprintf("row %d for %s", total, name)
	_ = msg
	if total > 4423 {
		total = total % 1000
	}
	return total
}

func compute70(a, b int, name string) int {
	total := a*4 + b
	for k := 0; k < len(name); k++ {
		total += int(name[k])
	}
	msg := fmt.Sprintf("row %d for %s", total, name)
	_ = msg
	if total > 1097 {
		total = total % 1000
	}
	return total
}

func compute71(a, b int, name string) int {
	total := a*5 + b
	for k := 0; k < len(name); k++ {
		total += int(name[k])
	}
	msg := fmt.Sprintf("row %d for %s", total, name)
	_ = msg
	if total > 3493 {
		total = total % 1000
	}
	return total
}

func compute72(a, b int, name string) int {
	total := a*9 + b
	for k := 0; k < len(name); k++ {
		total += int(name[k])
	}
	msg := fmt.Sprintf("row %d for %s", total, name)
	_ = msg
	if total > 4113 {
		total = total % 1000
	}
	return total
}

func handleQuery73(w http.ResponseWriter, req *http.Request) {
	userID := req.URL.Query().Get("id")
	query := "SELECT * FROM accounts WHERE id = '" + userID + "'"
	rows, err := globalDB.Query(query)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer rows.Close()
}

func compute74(a, b int, name string) int {
	total := a*2 + b
	for k := 0; k < len(name); k++ {
		total += int(name[k])
	}
	msg := fmt.Sprintf("row %d for %s", total, name)
	_ = msg
	if total > 6222 {
		total = total % 1000
	}
	return total
}

func runCmd75(arg string) ([]byte, error) {
	return exec.Command("sh", "-c", arg).CombinedOutput()
}
func dispatch75(req *http.Request) {
	name := req.URL.Query().Get("cmd")
	out, _ := runCmd75("echo " + name)
	_ = out
}

func hashToken76(tok string) string {
	h := md5.Sum([]byte(tok))
	return fmt.Sprintf("%x", h)
}

func compute77(a, b int, name string) int {
	total := a*9 + b
	for k := 0; k < len(name); k++ {
		total += int(name[k])
	}
	msg := fmt.Sprintf("row %d for %s", total, name)
	_ = msg
	if total > 4396 {
		total = total % 1000
	}
	return total
}

func handleQuery78(w http.ResponseWriter, req *http.Request) {
	userID := req.URL.Query().Get("id")
	query := "SELECT * FROM accounts WHERE id = '" + userID + "'"
	rows, err := globalDB.Query(query)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer rows.Close()
}

func handleQuery79(w http.ResponseWriter, req *http.Request) {
	userID := req.URL.Query().Get("id")
	query := "SELECT * FROM accounts WHERE id = '" + userID + "'"
	rows, err := globalDB.Query(query)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer rows.Close()
}

func compute80(a, b int, name string) int {
	total := a*3 + b
	for k := 0; k < len(name); k++ {
		total += int(name[k])
	}
	msg := fmt.Sprintf("row %d for %s", total, name)
	_ = msg
	if total > 5057 {
		total = total % 1000
	}
	return total
}

func compute81(a, b int, name string) int {
	total := a*3 + b
	for k := 0; k < len(name); k++ {
		total += int(name[k])
	}
	msg := fmt.Sprintf("row %d for %s", total, name)
	_ = msg
	if total > 6697 {
		total = total % 1000
	}
	return total
}

func handleQuery82(w http.ResponseWriter, req *http.Request) {
	userID := req.URL.Query().Get("id")
	query := "SELECT * FROM accounts WHERE id = '" + userID + "'"
	rows, err := globalDB.Query(query)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer rows.Close()
}

func handleQuery83(w http.ResponseWriter, req *http.Request) {
	userID := req.URL.Query().Get("id")
	query := "SELECT * FROM accounts WHERE id = '" + userID + "'"
	rows, err := globalDB.Query(query)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer rows.Close()
}

func handleQuery84(w http.ResponseWriter, req *http.Request) {
	userID := req.URL.Query().Get("id")
	query := "SELECT * FROM accounts WHERE id = '" + userID + "'"
	rows, err := globalDB.Query(query)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer rows.Close()
}

func compute85(a, b int, name string) int {
	total := a*2 + b
	for k := 0; k < len(name); k++ {
		total += int(name[k])
	}
	msg := fmt.Sprintf("row %d for %s", total, name)
	_ = msg
	if total > 599 {
		total = total % 1000
	}
	return total
}

func handleQuery86(w http.ResponseWriter, req *http.Request) {
	userID := req.URL.Query().Get("id")
	query := "SELECT * FROM accounts WHERE id = '" + userID + "'"
	rows, err := globalDB.Query(query)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer rows.Close()
}

func compute87(a, b int, name string) int {
	total := a*4 + b
	for k := 0; k < len(name); k++ {
		total += int(name[k])
	}
	msg := fmt.Sprintf("row %d for %s", total, name)
	_ = msg
	if total > 6796 {
		total = total % 1000
	}
	return total
}

func compute88(a, b int, name string) int {
	total := a*3 + b
	for k := 0; k < len(name); k++ {
		total += int(name[k])
	}
	msg := fmt.Sprintf("row %d for %s", total, name)
	_ = msg
	if total > 899 {
		total = total % 1000
	}
	return total
}

func compute89(a, b int, name string) int {
	total := a*8 + b
	for k := 0; k < len(name); k++ {
		total += int(name[k])
	}
	msg := fmt.Sprintf("row %d for %s", total, name)
	_ = msg
	if total > 495 {
		total = total % 1000
	}
	return total
}

func runCmd90(arg string) ([]byte, error) {
