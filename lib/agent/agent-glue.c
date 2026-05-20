#include "frida-agent.h"

#include "frida-base.h"
#include "frida-payload.h"

#ifdef HAVE_ANDROID
# include <jni.h>
# if __ANDROID_API__ < __ANDROID_API_L__
#  include <signal.h>
# endif
#endif
#if defined (HAVE_GIOAPPLE)
# include <gioapple.h>
#elif defined (HAVE_GIOOPENSSL)
# include <gioopenssl.h>
#endif

#ifdef HAVE_LINUX
# include <pthread.h>
# include <string.h>
# include <sys/prctl.h>
# include <gum/gum.h>
# include <gum/guminterceptor.h>

static int (* frida_real_pthread_setname_np) (pthread_t thread,
    const char * name);
static int (* frida_real_prctl) (int option, unsigned long arg2,
    unsigned long arg3, unsigned long arg4, unsigned long arg5);

static const char *
frida_sanitize_thread_name (const char * name)
{
  if (name == NULL)
    return name;
  if (strcmp (name, "gmain") == 0)
    return "Jit thread pool";
  if (strcmp (name, "gdbus") == 0)
    return "Binder:1";
  return name;
}

static int
frida_replacement_pthread_setname_np (pthread_t thread, const char * name)
{
  return frida_real_pthread_setname_np (thread,
      frida_sanitize_thread_name (name));
}

static int
frida_replacement_prctl (int option, unsigned long arg2, unsigned long arg3,
                         unsigned long arg4, unsigned long arg5)
{
  if (option == PR_SET_NAME)
  {
    arg2 = (unsigned long) frida_sanitize_thread_name (
        (const char *) arg2);
  }
  return frida_real_prctl (option, arg2, arg3, arg4, arg5);
}

static void
frida_install_thread_name_sanitizer (void)
{
  static gboolean installed = FALSE;
  GumInterceptor * interceptor;

  if (installed)
    return;
  installed = TRUE;

  gum_init_embedded ();
  interceptor = gum_interceptor_obtain ();
  gum_interceptor_begin_transaction (interceptor);
  gum_interceptor_replace (interceptor,
      GSIZE_TO_POINTER (pthread_setname_np),
      frida_replacement_pthread_setname_np,
      NULL,
      (gpointer *) &frida_real_pthread_setname_np);
  gum_interceptor_replace (interceptor,
      GSIZE_TO_POINTER (prctl),
      frida_replacement_prctl,
      NULL,
      (gpointer *) &frida_real_prctl);
  gum_interceptor_end_transaction (interceptor);
  g_object_unref (interceptor);
}
#endif

void
_frida_agent_environment_init (void)
{
#ifdef HAVE_MUSL
  static gboolean been_here = FALSE;

  if (been_here)
    return;
  been_here = TRUE;
#endif

#ifdef _MSC_VER
  frida_libc_shim_init ();
#endif
#ifdef HAVE_LINUX
  frida_install_thread_name_sanitizer ();
#endif
  gio_init ();

  g_thread_set_garbage_handler (_frida_agent_on_pending_thread_garbage, NULL);

#if defined (HAVE_GIOAPPLE)
  g_io_module_apple_register ();
#elif defined (HAVE_GIOOPENSSL)
  g_io_module_openssl_register ();
#endif

  gum_script_backend_get_type (); /* Warm up */
  frida_error_quark (); /* Initialize early so GDBus will pick it up */

#if defined (HAVE_ANDROID) && __ANDROID_API__ < __ANDROID_API_L__
  /*
   * We might be holding the dynamic linker's lock, so force-initialize
   * our bsd_signal() wrapper on this thread.
   */
  bsd_signal (G_MAXINT32, SIG_DFL);
#endif
}

void
_frida_agent_environment_deinit (void)
{
#ifndef HAVE_MUSL
  frida_libc_shim_prepare_to_deinit ();

  gum_shutdown ();
  gio_shutdown ();
  glib_shutdown ();

  gio_deinit ();

  frida_run_atexit_handlers ();

# if defined (_MSC_VER) || defined (HAVE_DARWIN)
  frida_libc_shim_deinit ();
# endif
#endif
}

#ifdef HAVE_ANDROID

jint
JNI_OnLoad (JavaVM * vm, void * reserved)
{
  FridaAgentBridgeState * state = reserved;

  frida_agent_main (state->agent_parameters, &state->unload_policy, state->injector_state);

  return JNI_VERSION_1_6;
}

#endif
