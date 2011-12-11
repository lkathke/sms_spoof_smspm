##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'
require 'rex'

class Metasploit4 < Msf::Auxiliary

	include Msf::Exploit::Remote::HttpClient
	include Msf::Auxiliary::Report

	def initialize(info = {})
		super(update_info(info,
			'Name' => 'Spoof SMS (SMSPM.COM)',
			'Description' => %q{
				This module uses the SMSPOINT API to send spoofed sms

				API: http://www.smspm.com/misc/docs/SMSPM_API_1.4.pdf

				Get secret hash: http://www.smspm.com/
			},
			'Author' =>
				[
					'Hugo Caron <y0ug[at]codsec.com>',
				],
			'License' => MSF_LICENSE
		))

		# disabling all the unnecessary options that someone might set to break our query
		deregister_options('RPORT','RHOST', 'BasicAuthPass', 'BasicAuthUser', 'DOMAIN',
			'DigestAuthIIS', 'SSLVersion', 'NTLM::SendLM', 'NTLM::SendNTLM',
			'NTLM::SendSPN', 'NTLM::UseLMKey', 'NTLM::UseNTLM2_session',
			'NTLM::UseNTLMv2', 'DigestAuthPassword', 'DigestAuthUser', 'SSL')

		register_options(
			[
				OptString.new('SECRETHASH', [true, "The SMSPOINT secret hash"]),
				OptString.new('PHONE', [true, "The recipient in international format"]),
				OptString.new('SENDER', [true, "Sender id can be a word or just a number"]),
				OptString.new('MSG', [true, "Message to send"]),
				OptBool.new('BALANCE', [false, "Only check the balance", false]),
				OptString.new('VHOST', [true, 'The virtual host name to use in requests', 'panel.smspm.com']),
			], self.class)
	end

	# create our Shodan query function that performs the actual web request


	def query_smspm(secrethash, action, param, type = 'GET')

		# build param
		data = ""
		param.each { |elem|
				data << "#{elem[0]}=#{elem[1]}"
				data << "&"
		}

		# eat last &
		data = data[0..-2]

		url = "/gateway/#{secrethash}/api.v1/#{action}?#{data}"

		res = send_request_raw(
			{
				'method'   => 'GET',
				'uri'      => url
		}, 25)

		# Check if we got a response, parse the JSON, and return it
		if (res)
			results = ActiveSupport::JSON.decode(res.body)
			return results
		else
			return 'server_error'
		end
	end

	def balance(secrethash)
		result = query_smspm(secrethash, 'balance', {})

		if result.empty?
			print_error("Check balance failed")
			return
		end
		if result['balance']
			print_status("You have #{result['balance']}€ on this account")
		else 
			print_error("Balance failed: #{result['error']['message']}")
		end
	end

	def sendsms(secrethash, param)
		result = query_smspm(secrethash, 'send', param)

		if result.empty?
			print_error("Send failed")
			return
		end

		if result['submitted'] == true
			print_status("Send successfully, id=#{result['id']}")
		else
			print_error("Send failed: #{result['error']['message']}")
		end
	end

	def cleanup
		datastore['RHOST'] = @old_rhost
		datastore['RPORT'] = @old_rport
	end

	def run
		secrethash = datastore['SECRETHASH']

		@res = Net::DNS::Resolver.new()
		dns_query = @res.query("#{datastore['VHOST']}", "A")
		if dns_query.answer.length == 0
			print_error("Could not resolve #{datastore['VHOST']}")
			return
		else
			# Make a copy of the original rhost
			@old_rhost = datastore['RHOST']
			@old_rport = datastore['RPORT']
			datastore['RHOST'] = dns_query.answer[0].to_s.split(/[\s,]+/)[4]
			datastore['RPORT'] = 80
		end

		if datastore['BALANCE']
			balance(secrethash)
			return
		end

		if datastore['PHONE'].chars.first == '+'
			datastore['PHONE'].slice!(0)
		end

		param = {
			:phone => datastore['PHONE'],
			:sender => Rex::Text.uri_encode(datastore['SENDER']),
			:message => Rex::Text.uri_encode(datastore['MSG']),
			:output => 'json',
		}

		print_status("Send from #{datastore['SENDER']} to #{datastore['PHONE']}")
		print_status("Message: #{datastore['MSG']}")

		sendsms(secrethash, param)
		balance(secrethash)
	end
end
