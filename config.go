/**
 * Created with IntelliJ IDEA.
 * User: clowwindy
 * Date: 12-11-2
 * Time: 上午10:31
 * To change this template use File | Settings | File Templates.
 */
package allproxy


type ClientConfig struct {
	Server     string `json:"server"`
	ServerPort int         `json:"server_port"`
	LocalAddress string	`json:local_address`
	LocalPort  int         `json:"local_port"`
	PassWord   string      `json:"password"`
	Method     string      `json:"method"` // encryption method

}


