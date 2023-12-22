unit SSLDemo.EncFrame;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants, System.Classes,
  Vcl.Graphics, Vcl.Controls, Vcl.Forms, Vcl.Dialogs, Vcl.StdCtrls;

type
  TEncFrame = class(TFrame)
    btnEncrypt: TButton;
    memTest: TMemo;
    btnDecrypt: TButton;
    Label1: TLabel;
    Label2: TLabel;
    edtInputFileName: TEdit;
    edtOutputFileName: TEdit;
    chkBase64: TCheckBox;
    BtnGenrateFile: TButton;
    cmbCipher: TComboBox;
    Label3: TLabel;
    procedure btnEncryptClick(Sender: TObject);
    procedure btnDecryptClick(Sender: TObject);
    procedure BtnGenrateFileClick(Sender: TObject);
  private
    { Private declarations }
  public
    constructor Create(AOwner: TComponent); override;
  end;

implementation

{$R *.dfm}

uses
  OpenSSL.EncUtils;

procedure TEncFrame.btnEncryptClick(Sender: TObject);
var
  EncUtil :TEncUtil;
begin
  EncUtil := TEncUtil.Create;
  try
    EncUtil.UseBase64 := chkBase64.Checked;
    EncUtil.Passphrase := InputBox(Name, 'password', '');
    EncUtil.Cipher := cmbCipher.Text;
    EncUtil.Encrypt(edtInputFileName.Text, edtOutputFileName.Text);
  finally
    EncUtil.Free;
  end;
end;

procedure TEncFrame.BtnGenrateFileClick(Sender: TObject);
begin
  memTest.Lines.SaveToFile(edtInputFileName.Text);
end;

constructor TEncFrame.Create(AOwner: TComponent);
var
  TestFolder :string;
begin
  inherited;
  TestFolder := StringReplace(ExtractFilePath(ParamStr(0)), 'Samples\SSLDemo', 'TestData', [rfReplaceAll, rfIgnoreCase]);

  edtInputFileName.Text := TestFolder + 'AES_TEST_CLEAR.txt';
  edtOutputFileName.Text := TestFolder + 'AES_TEST_ENC.txt';
  TEncUtil.SupportedCiphers(cmbCipher.Items);
end;

procedure TEncFrame.btnDecryptClick(Sender: TObject);
var
  EncUtil :TEncUtil;
begin
  EncUtil := TEncUtil.Create;
  try
    EncUtil.UseBase64 := chkBase64.Checked;
    EncUtil.Passphrase := InputBox(Name, 'password', '');
    EncUtil.Cipher := cmbCipher.Text;
    EncUtil.Decrypt(edtOutputFileName.Text, edtInputFileName.Text);
  finally
    EncUtil.Free;
  end;
end;

end.
