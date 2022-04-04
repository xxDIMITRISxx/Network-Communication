# Network-Communication
A secure, asynchronous, peer to peer chat application Project which the Network communications is conducted via TCP using Python.
It is a socket chat application, without using Threading. 

<h2>How it works </h2>
<ol>
  <li>Start the programme</li>
  <li>Ask the user for the following information:
    <ul> 
      <li>A port on the machine to act for incoming connections </li>
      <li>A file which contains the directory of individuals to contact</li>
    </ul>
  </li>
  <li>Open Server TCP socket locally on port specified by the user</li>
  <li>Load up the directory (specification below)
    <ul> 
      <li>This is a JSON serialised dictionary format</li>
    </ul>
  </li>
  <li>Wait for either an incoming network message or a message to be sent from user</li>
  <li>If an incoming network message
    <ul>
      <li>Connect to the destination using the decided protocol</li>
      <li>Receive Message – Message format below</li>
      <li>Check the control information for consistency</li>
      <li>Display received message to the user</li>
      <li> Terminate Connection</li>
    </ul>
  </li>
  <li>If message to be sent:
    <ul>
      <il>Wait for the message to be completed</il>
      <il>Request destination from user.</il>
      <il>Open socket to destination</il>
      <il>Connect to the destination using the decided protocol</il>
      <il>Send Message – Message format below</il>
      <il>Display transmission success or failure message to user</il>
      <li>Terminate Connection</li>
    </ul>
  </li>
  <li> Go to step 3</li>
  </ol>
  
 <h3>Message Format:</h3>
 <p>Python Dictionary message format that can be serialised as follows:</p>
 <p>Message = {‘header’:{‘crc’: val, ‘timestamp’: UTC_val}, ‘message’: base64_encoded_text_message,
 ‘security’:{‘hmac’: {‘hmac_type’: val, ‘hmac_val’: val}, ‘enc_type’: val}}</p>
 
  <h3>Directory Format:</h3>
 <p>Python list of Dictionary message format that can be serialised as follows:</p>
 <p>Directory = [{'username': val, 'password': val, 'port': val, 'ip':' val '}, {'username': val, 'password': val,
'port': val, 'ip':' val '}, …]</p>
 
 
 <h4>Extra info</h4>
 <p>The <b>file_writter.py</b> file, needs to run first so you can write some data to the <i>Directories</i></p>
