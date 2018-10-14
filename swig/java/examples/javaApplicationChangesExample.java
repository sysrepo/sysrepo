/**
 * @file javaApplicationChangesExample.java
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

/* Function for printing out values depending on their type. */
class Print {
	/* Helper function for printing changes given operation, old and new value. */
	public void change(sr_change_oper_t op, Val old_val, Val new_val) {
		if (op == sr_change_oper_t.SR_OP_CREATED) {
			System.out.print("CREATED: ");
			System.out.print(new_val.to_string());
		} else if (op == sr_change_oper_t.SR_OP_DELETED) {
			System.out.print("DELETED: ");
			System.out.print(old_val.to_string());
		} else if (op == sr_change_oper_t.SR_OP_MODIFIED) {
			System.out.print("MODIFIED: ");
			System.out.print("old value");
			System.out.print(old_val.to_string());
			System.out.print("new value");
			System.out.print(new_val.to_string());
		} else if (op == sr_change_oper_t.SR_OP_MOVED) {
			System.out.print( "MOVED: " + new_val.xpath() + " after " + old_val.xpath());
		}
	}

	/* Helper function for printing events. */
	public String ev_to_str(sr_notif_event_t ev) {
		if (ev == sr_notif_event_t.SR_EV_VERIFY) {
			return "verify";
		} else if (ev == sr_notif_event_t.SR_EV_APPLY) {
			return "apply";
		} else if (ev == sr_notif_event_t.SR_EV_ABORT) {
			return "abort";
		} else {
			return "abort";
		}
	}

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

		try {
			Print print = new Print();
			System.out.println("\n\n ========== Notification " + print.ev_to_str(event) + " =============================================\n");
			if (sr_notif_event_t.SR_EV_APPLY == event) {
				print.current_config(sess, module_name);

				System.out.println("\n\n ========== CONFIG HAS CHANGED, CURRENT RUNNING CONFIG: ==========\n");
			}

			System.out.println("\n\n ========== CHANGES: =============================================\n");

			String change_path = "/" + module_name + ":*";

			Iter_Change it = sess.get_changes_iter(change_path);

			while (true) {
				Change change = sess.get_change_next(it);
				if (change == null)
					break;
				print.change(change.oper(), change.old_val(), change.new_val());
			}

			System.out.println("\n\n ========== END OF CHANGES =======================================\n");
		} catch (Exception e) {
			System.out.println(e);
		}
                return sr_error_t.SR_ERR_OK.swigValue();
	}
}

/* Notable difference between c implementation is using exception mechanism for open handling unexpected events.
 * Here it is useful because `Conenction`, `Session` and `Subscribe` could throw an exception. */
public class javaApplicationChangesExample {
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
			subscribe.module_change_subscribe(module_name, cb);

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
