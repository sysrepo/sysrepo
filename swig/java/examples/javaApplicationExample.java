/**
 * @file javaApplicationExample.java
 * @author Mislav Novakovic <mislav.novakovic@sartura.hr>
 * @brief An example for Java bindings.
 *
 * @copyright
 * Copyright 2016 Deutsche Telekom AG.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
import org.sysrepo.*;

import java.io.*;
import java.util.Scanner;

class Print {
	/* Function to print current configuration state.
	 * It does so by loading all the items of a session and printing them out. */
	public void current_config(Session session, String module_name) {
		String select_xpath = "/" + module_name + ":*//*";

		Vals values = session.get_items(select_xpath);

		for (int i = 0; i < values.val_cnt(); i++) {
			System.out.print(values.val(i).to_string());
		}
	}
}

class My_Callback extends Callback {
	/* Function to be called for subscribed client of given session whenever configuration changes. */
	public int module_change(Session sess, String module_name, sr_notif_event_t event, SWIGTYPE_p_void private_ctx) {
		System.out.println("\n\n ========== CONFIG HAS CHANGED, CURRENT RUNNING CONFIG: ==========\n");

		Print print = new Print();
		print.current_config(sess, module_name);
                return sr_error_t.SR_ERR_OK.swigValue();
	}
}

/* Notable difference between c implementation is using exception mechanism for open handling unexpected events.
 * Here it is useful because `Conenction`, `Session` and `Subscribe` could throw an exception. */
public class javaApplicationExample {
	static {
		System.loadLibrary("sysrepoJava");
		// System.loadLibrary("libsysrepoJava");
	}
	public static void main(String argv[]) {
		try {
			String module_name = "ietf-interfaces";

			// connect to sysrepo
			Connection conn = new Connection("example_application");

			// start session
			Session sess = new Session(conn);

			// subscribe for changes in running config
			Subscribe subscribe = new Subscribe(sess);

			My_Callback cb = new My_Callback();

			subscribe.module_change_subscribe(module_name, cb, null, 0, sr_subscr_flag_t.SR_SUBSCR_DEFAULT.swigValue() | sr_subscr_flag_t.SR_SUBSCR_APPLY_ONLY.swigValue());

			System.out.println("\n\n ========== READING STARTUP CONFIG: ==========\n");

			try {
				Print print = new Print();
				print.current_config(sess, module_name);
			} catch (Exception e) {
				System.out.println(e);
			}

			boolean repeat = true;
			Scanner keyboard = new Scanner(System.in);
			while (repeat) {
				repeat = keyboard.nextBoolean();
			}

			System.out.println("Application exit requested, exiting.\n");

		} catch (Exception e) {
			System.out.println(e);
		}
	}
}
