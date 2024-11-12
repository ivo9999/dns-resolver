package dns

import (
	"bufio"
	"crypto/rand"
	"fmt"
	"math/big"
	"net"
	"strings"

	"golang.org/x/net/dns/dnsmessage"
)

const ROOT_SERVERS = "198.41.0.4,199.9.14.201,192.33.4.12,199.7.91.13,192.203.230.10,192.5.5.241,192.112.36.4,198.97.190.53"

func handlePacket(pc net.PacketConn, addr net.Addr, buf []byte) error {
	p := dnsmessage.Parser{}

	header, err := p.Start(buf)
	if err != nil {
		return fmt.Errorf("error parsing packet: %s", err)
	}

	question, err := p.Question()
	if err != nil {
		return err
	}

	response, err := dnsQuery(getRootServers(), question)
	if err != nil {
		return err
	}

	response.Header.ID = header.ID

	responseBuffer, err := response.Pack()
	if err != nil {
		return err
	}

	_, err = pc.WriteTo(responseBuffer, addr)
	if err != nil {
		return err
	}
	return nil
}

func dnsQuery(servers []net.IP, question dnsmessage.Question) (*dnsmessage.Message, error) {
	for i := 0; i < 3; i++ {
		dnsAnswer, header, err := outgoingDnsQuery(servers, question)
		if err != nil {
			return nil, err
		}

		parsedAnswers, err := dnsAnswer.AllAnswers()
		if err != nil {
			return nil, err
		}

		if header.Authoritative {
			return &dnsmessage.Message{
				Header:  dnsmessage.Header{Response: true, RCode: dnsmessage.RCodeSuccess},
				Answers: parsedAnswers,
			}, nil
		}

		authorities, err := dnsAnswer.AllAuthorities()
		if err != nil {
			return nil, err
		}

		if len(authorities) == 0 {
			return &dnsmessage.Message{
				Header: dnsmessage.Header{RCode: dnsmessage.RCodeServerFailure},
			}, nil
		}

		nameServers := make([]string, len(authorities))

		for k, authority := range authorities {
			if authority.Header.Type == dnsmessage.TypeNS {
				nameServers[k] = authority.Body.(*dnsmessage.NSResource).NS.String()
			}
		}

		additionals, err := dnsAnswer.AllAdditionals()
		if err != nil {
			return nil, err
		}

		newResolverServersFound := false
		servers = []net.IP{}

		for _, additional := range additionals {
			if additional.Header.Type == dnsmessage.TypeA {
				for _, nameServer := range nameServers {
					if nameServer == additional.Header.Name.String() {
						newResolverServersFound = true
						servers = append(servers, additional.Body.(*dnsmessage.AResource).A[:])
					}
				}
			}
		}

		if !newResolverServersFound {
			for _, nameServer := range nameServers {
				if !newResolverServersFound {
					response, err := dnsQuery(getRootServers(),
						dnsmessage.Question{Name: dnsmessage.MustNewName(nameServer), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET})
					if err != nil {
						return nil, err
					} else {
						newResolverServersFound = true
						for _, answer := range response.Answers {
							if answer.Header.Type == dnsmessage.TypeA {
								servers = append(servers, answer.Body.(*dnsmessage.AResource).A[:])
							}
						}
					}
				}
			}
		}

	}

	return &dnsmessage.Message{
		Header: dnsmessage.Header{RCode: dnsmessage.RCodeServerFailure},
	}, nil
}

func HandlePacket(pc net.PacketConn, addr net.Addr, buf []byte) error {
	if err := handlePacket(pc, addr, buf); err != nil {
		return fmt.Errorf("error handling packet: %s", err)
	}
	return nil
}

func outgoingDnsQuery(servers []net.IP, question dnsmessage.Question) (*dnsmessage.Parser, *dnsmessage.Header, error) {
	max := ^uint16(0)
	randomNumber, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		return nil, nil, err
	}
	message := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:               uint16(randomNumber.Int64()),
			OpCode:           dnsmessage.OpCode(0),
			Response:         false,
			AuthenticData:    false,
			RecursionDesired: false,
		},
		Questions: []dnsmessage.Question{
			question,
		},
	}
	buf, err := message.Pack()
	if err != nil {
		return nil, nil, fmt.Errorf("Pack error: %s", err)
	}

	var conn net.Conn

	for _, server := range servers {
		conn, err = net.Dial("udp", server.String()+":53")
		if err == nil {
			break
		}
	}
	if conn == nil {
		return nil, nil, fmt.Errorf("no servers available")
	}

	_, err = conn.Write(buf)
	if err != nil {
		return nil, nil, fmt.Errorf("write error: %s", err)
	}

	answer := make([]byte, 512)

	n, err := bufio.NewReader(conn).Read(answer)
	if err != nil {
		return nil, nil, err
	}

	conn.Close()

	var p dnsmessage.Parser

	header, err := p.Start(answer[:n])
	if err != nil {
		return nil, nil, fmt.Errorf("start error: %s", err)
	}

	questions, err := p.AllQuestions()
	if err != nil {
		return nil, nil, fmt.Errorf("all questions error: %s", err)
	}

	if len(questions) != len(message.Questions) {
		return nil, nil, fmt.Errorf("answer packet doesnt have the same amount of questions")
	}

	err = p.SkipAllQuestions()
	if err != nil {
		return nil, nil, err
	}

	return &p, &header, nil
}

func getRootServers() []net.IP {
	rootServers := []net.IP{}

	for _, server := range strings.Split(ROOT_SERVERS, ",") {
		rootServers = append(rootServers, net.ParseIP(server))
	}

	return rootServers
}
