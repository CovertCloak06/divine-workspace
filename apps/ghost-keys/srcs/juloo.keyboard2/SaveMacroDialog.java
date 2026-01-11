package juloo.keyboard2;

import android.app.AlertDialog;
import android.content.Context;
import android.content.DialogInterface;
import android.text.InputType;
import android.view.WindowManager;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.TextView;

/**
 * Dialog for saving a new macro.
 * Shows an input field for the macro name.
 */
public class SaveMacroDialog
{
  public interface OnSaveListener
  {
    void onSave(String label, String command);
    void onCancel();
  }

  private Context _context;
  private String _command;
  private OnSaveListener _listener;

  public SaveMacroDialog(Context context, String command, OnSaveListener listener)
  {
    _context = context;
    _command = command;
    _listener = listener;
  }

  public void show()
  {
    AlertDialog.Builder builder = new AlertDialog.Builder(_context);
    builder.setTitle("Save Macro");

    LinearLayout layout = new LinearLayout(_context);
    layout.setOrientation(LinearLayout.VERTICAL);
    int padding = (int) (16 * _context.getResources().getDisplayMetrics().density);
    layout.setPadding(padding, padding, padding, padding);

    // Show the command being saved
    TextView commandLabel = new TextView(_context);
    commandLabel.setText("Command:");
    commandLabel.setTextColor(0xFF888888);
    layout.addView(commandLabel);

    TextView commandText = new TextView(_context);
    String displayCmd = _command;
    if (displayCmd.endsWith("\n"))
      displayCmd = displayCmd.substring(0, displayCmd.length() - 1);
    if (displayCmd.length() > 50)
      displayCmd = displayCmd.substring(0, 47) + "...";
    commandText.setText(displayCmd);
    commandText.setTextColor(0xFF00FFFF);
    commandText.setPadding(0, 0, 0, padding);
    layout.addView(commandText);

    // Label input
    TextView nameLabel = new TextView(_context);
    nameLabel.setText("Name this macro:");
    nameLabel.setTextColor(0xFFE0E0E0);
    layout.addView(nameLabel);

    final EditText input = new EditText(_context);
    input.setInputType(InputType.TYPE_CLASS_TEXT);
    input.setHint("e.g., Deploy, Edit HTML, Backup");
    input.setTextColor(0xFFE0E0E0);
    input.setHintTextColor(0xFF666666);
    layout.addView(input);

    builder.setView(layout);

    builder.setPositiveButton("Save", new DialogInterface.OnClickListener()
    {
      @Override
      public void onClick(DialogInterface dialog, int which)
      {
        String label = input.getText().toString().trim();
        if (!label.isEmpty() && _listener != null)
        {
          _listener.onSave(label, _command);
        }
      }
    });

    builder.setNegativeButton("Cancel", new DialogInterface.OnClickListener()
    {
      @Override
      public void onClick(DialogInterface dialog, int which)
      {
        if (_listener != null)
          _listener.onCancel();
        dialog.cancel();
      }
    });

    AlertDialog dialog = builder.create();

    // Make dialog appear above keyboard
    if (dialog.getWindow() != null)
    {
      dialog.getWindow().setType(WindowManager.LayoutParams.TYPE_APPLICATION_ATTACHED_DIALOG);
      dialog.getWindow().addFlags(WindowManager.LayoutParams.FLAG_ALT_FOCUSABLE_IM);
    }

    dialog.show();
  }
}
